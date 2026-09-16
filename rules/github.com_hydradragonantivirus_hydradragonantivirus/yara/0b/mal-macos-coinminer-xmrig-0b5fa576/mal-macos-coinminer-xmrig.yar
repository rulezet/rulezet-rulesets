rule mal_macos_coinminer_xmrig {
  meta:
    description = "Identify macOS CoinMiner malware."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.05"
    sample      = "fabe0b41fb5bce6bda8812197ffd74571fc9e8a5a51767bcceef37458e809c5c"
    DaysofYARA  = "64/100"

  strings:
    $s0 = "XMRig"
    $s1 = "cryptonight"
    $s3 = "user\": \"pshp"
    $s4 = "pass\": \"x"
    $s5 = "url\": \"127.0.0.1:"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}