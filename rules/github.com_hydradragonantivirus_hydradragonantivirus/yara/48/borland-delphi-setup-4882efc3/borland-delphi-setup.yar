import "pe"
rule borland_delphi_setup {
  meta:
    author      = "PEiD"
    description = "Borland Delphi Setup Module"
    group       = "11"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }

  condition:
    $a0 at pe.entry_point
}