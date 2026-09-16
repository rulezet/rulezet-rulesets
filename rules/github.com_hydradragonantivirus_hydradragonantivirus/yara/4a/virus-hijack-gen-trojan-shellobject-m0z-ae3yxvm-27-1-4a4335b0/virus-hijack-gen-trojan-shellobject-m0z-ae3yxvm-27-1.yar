rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_27_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72a5fc496484b91f0cabaab9109235aaed3436f436ddcdfaf9bcecd6aa2da950"

  strings:
    $s1 = "address family not ?" fullword ascii
    $s2 = "eAse!O" fullword ascii
    $s3 = "P\\&guard" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}