rule Virus_Hijack_Trojan_GenericKDZ_98113_139 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_139.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d76a6e9560c4ea60ddcea5bbf0cb382178967a65c60f16c76c2b64bdbc1d036d"

  strings:
    $s1 = "yby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}