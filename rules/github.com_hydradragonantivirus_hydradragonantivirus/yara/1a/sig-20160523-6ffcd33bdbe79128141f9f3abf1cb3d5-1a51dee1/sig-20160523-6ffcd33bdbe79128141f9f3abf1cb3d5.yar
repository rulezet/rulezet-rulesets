rule sig_20160523_6ffcd33bdbe79128141f9f3abf1cb3d5 {
  meta:
    description = "datamaliciousorder - file 20160523_6ffcd33bdbe79128141f9f3abf1cb3d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d74ae8e59ccfadd77a9680a1d52e0d2e640d6a66ac7648dd8e6de2d156f53aa"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}