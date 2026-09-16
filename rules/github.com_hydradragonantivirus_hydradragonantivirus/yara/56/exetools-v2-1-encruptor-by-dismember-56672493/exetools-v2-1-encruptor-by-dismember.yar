import "pe"
rule ExeTools_v2_1_Encruptor_by_DISMEMBER {
  strings:
    $a0 = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74 }

  condition:
    $a0 at pe.entry_point
}