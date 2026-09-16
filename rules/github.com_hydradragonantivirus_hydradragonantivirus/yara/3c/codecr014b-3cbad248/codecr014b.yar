import "pe"
rule codecr014b {
  meta:
    author      = "PEiD"
    description = "CodeCrypt 0.14B -> defiler"
    group       = "110"
    function    = "0"

  strings:
    $a0 = { E9 C5 02 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

  condition:
    $a0 at pe.entry_point
}