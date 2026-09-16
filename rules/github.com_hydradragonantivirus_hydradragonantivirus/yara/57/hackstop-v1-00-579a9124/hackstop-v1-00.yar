import "pe"
rule HACKSTOP_v1_00 {
  strings:
    $a0 = { FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

  condition:
    $a0 at pe.entry_point
}