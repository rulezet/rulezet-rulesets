rule sig_20160405_797c17c569852addda591cc3e586a784 {
  meta:
    description = "datamaliciousorder - file 20160405_797c17c569852addda591cc3e586a784.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b4cd97d3b608f6a78c4e2cdf201e7cd505787015b4d9ee30c799b9090f11f9a"

  strings:
    $s1 = "deras = this;" fullword ascii
    $s2 = "print(leri);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}