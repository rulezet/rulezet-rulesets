rule Virus_Hijack_Gen_Trojan_ShellObject_A8Z_a0oa39p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.A8Z@a0oa39p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f08ca756c36edc6ed2a59075dd924b66dc07025cd9e5320b93eee0a148a5fba0"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<Module>{5d4472b8-0150-4841-8b31-c8fc27c38592}" fullword ascii
    $s3 = "Tied<G" fullword ascii
    $s4 = "sNee%~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}