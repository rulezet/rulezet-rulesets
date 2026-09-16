rule alexp10b2 {
  meta:
    author      = "PEiD"
    description = "Alex Protector 1.0 beta2"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 ?? E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 ?? ?? ?? 02 33 }

  condition:
    $a0
}