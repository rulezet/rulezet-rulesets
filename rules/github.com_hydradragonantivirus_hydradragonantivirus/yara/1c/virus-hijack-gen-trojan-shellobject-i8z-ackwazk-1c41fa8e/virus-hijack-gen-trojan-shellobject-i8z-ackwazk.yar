rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e099e31d384d856a419712ba4a1e7eaf26f092dcc96bf3d1ea1a8c0ae5dd789f"

  strings:
    $s1 = "gby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}