import "pe"
rule ms_vb_dll {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual Basic 6.0 DLL"
    group       = "16"
    function    = "0"

  strings:
    $a0 = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }

  condition:
    $a0 at pe.entry_point
}