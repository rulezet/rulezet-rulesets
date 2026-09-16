rule mal_macos_smoothoperator {
  meta:
    description = "Identify macOS SmoothOperator first stage."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.30"
    references  = "https://objective-see.org/blog/blog_0x73.html"
    sample      = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
    DaysofYARA  = "89/100"

  strings:
    $s0 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Safari/53" xor(0x01-0xff)
    $s1 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma" xor(0x01-0xff)
    $s2 = "%s/Library/Application Support/3CX Desktop App/%" xor(0x01-0xff)
    $s3 = "/System/Library/CoreServices/SystemVersion.plist" xor(0x01-0xff)

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    2 of them
}