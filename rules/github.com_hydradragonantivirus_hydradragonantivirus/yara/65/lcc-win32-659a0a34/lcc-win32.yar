import "pe"
rule lcc_win32 {
  meta:
    author      = "PEiD"
    description = "LCC Win32 1.x -> Jacob Navia"
    group       = "12"
    function    = "0"

  strings:
    $a0 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }

  condition:
    $a0 at pe.entry_point
}