import "pe"
rule FASM_v1_3x {
  strings:
    $a0 = { 6A ?? FF 15 ?? ?? ?? ?? A3 }

  condition:
    $a0 at pe.entry_point
}