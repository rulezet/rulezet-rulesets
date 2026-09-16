rule Virus_Hijack_Gen_Trojan_ShellObject_m8W_aW0I0Cd_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d196b0641915df950e0f3603c861558d5fe3db3f0d15805e225305bdade4b820"

  strings:
    $s1 = "tjxgt(plud" fullword ascii
    $s2 = "Java(TM) Web Start 11.281.2.09-fcs" fullword wide
    $s3 = "t(plud" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}