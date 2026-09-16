import "pe"
rule ming_gcc2 {
  meta:
    author      = "PEiD"
    description = "MingWin32 GCC 2.x"
    group       = "21"
    function    = "0"

  strings:
    $a0 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }

  condition:
    $a0 at pe.entry_point
}