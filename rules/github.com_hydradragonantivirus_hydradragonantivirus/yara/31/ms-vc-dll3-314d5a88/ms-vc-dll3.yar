import "pe"
rule ms_vc_dll3 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ DLL Method 3"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 53 B8 01 ?? ?? ?? 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }

  condition:
    $a0 at pe.entry_point
}