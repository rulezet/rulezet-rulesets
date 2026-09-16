import "pe"
rule ming_gcc3 {
  meta:
    author      = "PEiD"
    description = "MingWin32 GCC 3.x"
    group       = "21"
    function    = "0"

  strings:
    $a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 }

  condition:
    $a0 at pe.entry_point
}