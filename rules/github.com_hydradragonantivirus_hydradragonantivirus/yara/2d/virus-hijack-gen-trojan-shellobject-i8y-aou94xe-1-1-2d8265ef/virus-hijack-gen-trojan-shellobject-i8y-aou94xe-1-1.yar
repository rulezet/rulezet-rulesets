rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aOU94xe_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11f8ae188df70860b1aa10810c736967c2eca73ebe6de4d68a33502fed747e3"

  strings:
    $s1 = "MR-200019-42-S24-001 Special Project Material Specifications.exe" fullword wide
    $s2 = "  'description': 'A person'," fullword wide
    $s3 = "string encryptionT" fullword ascii
    $s4 = "Feature#type renaming pattern 'Cxtrdrzgu'.*T" fullword ascii
    $s5 = "Feature-rename symbol names with printable charactersT" fullword ascii
    $s6 = "code control flow obfuscationT" fullword ascii
    $s7 = "MR-200019-42-S24-001 Special Project Material Specifications" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}