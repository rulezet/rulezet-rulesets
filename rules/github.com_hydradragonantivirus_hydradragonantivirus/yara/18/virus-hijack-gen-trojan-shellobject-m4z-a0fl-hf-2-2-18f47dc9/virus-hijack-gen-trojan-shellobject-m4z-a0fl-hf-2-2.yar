rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_a0fL_hf_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffc838d13aaf2b260edf5385e2b28c7f11a244c6c3035c9e0d67f1820c2c9367"

  strings:
    $s1 = "<description>Flick Learning Wizard Application</description>" fullword ascii
    $s2 = "OYvP\\lMYfKX`IVoNXhCX_>X\\<OrNa" fullword ascii
    $s3 = "Flicks Training" fullword wide
    $s4 = "/% 4()@33L>BaLd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}