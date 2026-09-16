import "pe"
rule shrinker32 {
  meta:
    author      = "PEiD"
    description = "Shrinker 3.2 -> Blink Inc."
    group       = "172"
    function    = "0"

  strings:
    $a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 ?? 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }

  condition:
    $a0 at pe.entry_point
}