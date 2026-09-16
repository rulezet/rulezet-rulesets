import "pe"
rule Pksmart_1_0b {
  strings:
    $a0 = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3 }

  condition:
    $a0 at pe.entry_point
}