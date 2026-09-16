rule sig_20150827_73f9ab379c1d6374553f21b50614eae8 {
  meta:
    description = "datamaliciousorder - file 20150827_73f9ab379c1d6374553f21b50614eae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cba3ec73e8cf5eb7aa85ab523b9dc74466648e0bbb15b5ab0843dc270817b6e"

  strings:
    $s1 = "var key = 'ghk3Shvl5u';var b = '\"\\x189V\\x0b\\x0e\\x184_4_HV\\x13q\\x05D[\\x17Njb\\x0dF=\\x0b\\x02\\x05Z\\x1bG-\\x1ba60\\x10" ascii
    $s2 = "dtWe7)), ErMGYcBLEtddtWe7++, ErMGYcBLEtddtWe7 == key.length && (ErMGYcBLEtddtWe7 = 0);print(ErMGYcBLEtddtWe5);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}