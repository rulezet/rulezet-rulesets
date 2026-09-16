rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85d2df3cf89c64a4948c8873df29f19bf4b05bb8846163f1b73cbc38009e4346"

  strings:
    $s1 = "Wautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}