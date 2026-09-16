rule wcrt {
  meta:
    author      = "PEiD"
    description = "WCRT Library (Visual C++) Method 1 -> Jibz"
    group       = "17"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 EC 44 A1 ?? ?? ?? ?? 85 C0 74 ?? FF D0 85 C0 75 ?? 6A FE EB ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }

  condition:
    $a0
}