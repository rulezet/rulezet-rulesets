import "pe"
rule ms_vc620 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ 6.20"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }

  condition:
    $a0 at pe.entry_point
}