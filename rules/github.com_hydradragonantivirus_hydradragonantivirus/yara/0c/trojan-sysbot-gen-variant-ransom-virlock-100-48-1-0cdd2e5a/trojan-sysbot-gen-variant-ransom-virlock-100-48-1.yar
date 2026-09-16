rule Trojan_Sysbot_Gen_Variant_Ransom_VirLock_100_48_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5cdfe0d97c7ca4208b87c9b36ecd536597f32437a9d1e9223bc375e52b78c24"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}