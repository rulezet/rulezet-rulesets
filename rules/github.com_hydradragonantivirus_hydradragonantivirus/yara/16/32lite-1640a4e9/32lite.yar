import "pe"
rule _32lite {
  meta:
    author      = "PEiD"
    description = "32Lite 0.03a -> Oleg Prokhorov"
    group       = "101"
    function    = "0"

  strings:
    $a0 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }

  condition:
    $a0 at pe.entry_point
}