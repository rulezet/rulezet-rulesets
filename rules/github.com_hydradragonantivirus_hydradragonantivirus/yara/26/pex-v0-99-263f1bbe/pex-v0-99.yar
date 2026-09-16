import "pe"
rule PEX_v0_99 {
  strings:
    $a0 = { E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }
    $a1 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}