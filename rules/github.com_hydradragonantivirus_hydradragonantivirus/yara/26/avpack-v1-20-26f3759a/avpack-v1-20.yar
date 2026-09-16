import "pe"
rule AVPACK_v1_20 {
  strings:
    $a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB }

  condition:
    $a0 at pe.entry_point
}