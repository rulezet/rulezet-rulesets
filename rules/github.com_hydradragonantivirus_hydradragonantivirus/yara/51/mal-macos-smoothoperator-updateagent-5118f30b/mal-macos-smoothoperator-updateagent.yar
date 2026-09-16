rule mal_macos_smoothoperator_updateagent {
  meta:
    description = "Identify macOS SmoothOperator second stage."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.04.03"
    references  = "https://objective-see.org/blog/blog_0x74.html"
    sample      = "6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59"
    DaysofYARA  = "93/100"

  strings:
    $s0 = "https://sbmsa.wiki/blog/_insert"
    $s1 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma=true" xor
    $s2 = "%s/Library/Application Support/3CX Desktop App/config.json" xor
    $s3 = "%s/Library/Application Support/3CX Desktop App/.main_storage" xor
    $s4 = "gzip, deflate" xor(0x01-0xff)
    $s5 = "User-Agent" xor(0x01-0xff)
    $s6 = "Connection" xor(0x01-0xff)

    $f0 = "parse_json_config"
    $f1 = "enc_text"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    2 of ($s*) or
    all of ($f*)
}