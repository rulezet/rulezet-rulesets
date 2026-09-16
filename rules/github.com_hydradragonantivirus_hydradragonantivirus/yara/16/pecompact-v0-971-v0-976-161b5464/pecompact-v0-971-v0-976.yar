import "pe"
rule PECompact_v0_971___v0_976 {
  strings:
    $a0 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

  condition:
    $a0 at pe.entry_point
}