rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_ay8bj9g {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@ay8bj9g.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef1f26715a8ff0f6e72eaa751b1873b5e59d3547008e520a63e922cec005afa6"

  strings:
    $s1 = "\"must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}