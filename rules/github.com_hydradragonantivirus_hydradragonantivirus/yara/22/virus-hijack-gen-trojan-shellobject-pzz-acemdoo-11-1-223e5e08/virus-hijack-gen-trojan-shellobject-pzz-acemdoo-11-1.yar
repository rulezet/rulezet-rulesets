rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b820003e289bea27fdbbb4fb515dffa6d28cea11e67f700731c965c6cc3e5484"

  strings:
    $s1 = "`COlD<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}