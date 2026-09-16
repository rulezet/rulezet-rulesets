rule sig_20160523_3d4ab9a509a8776c109046d7e373c5b0 {
  meta:
    description = "datamaliciousorder - file 20160523_3d4ab9a509a8776c109046d7e373c5b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3b69c7ef60b38aa30554b7f9448a1e1bb7e9ec75a98e35ae819092a4f9926d4"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}