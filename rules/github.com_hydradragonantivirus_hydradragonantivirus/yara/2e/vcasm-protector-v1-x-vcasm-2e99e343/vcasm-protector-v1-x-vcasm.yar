import "pe"
rule Vcasm_Protector_V1_X____vcasm {
  strings:
    $a0 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }

  condition:
    $a0 at pe.entry_point
}