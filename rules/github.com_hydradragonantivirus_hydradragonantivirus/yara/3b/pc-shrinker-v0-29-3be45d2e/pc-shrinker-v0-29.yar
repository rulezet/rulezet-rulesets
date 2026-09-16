import "pe"
rule PC_Shrinker_v0_29 {
  strings:
    $a0 = { BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }

  condition:
    $a0 at pe.entry_point
}