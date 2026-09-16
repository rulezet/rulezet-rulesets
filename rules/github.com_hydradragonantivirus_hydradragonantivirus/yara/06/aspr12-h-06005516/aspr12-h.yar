rule aspr12_h {
  meta:
    author      = "PEiD"
    description = "ASProtect 1.2x [New Strain] -> Alexey Solodovnikov"
    group       = "106"
    function    = "3"

  strings:
    $a0 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }

  condition:
    $a0
}