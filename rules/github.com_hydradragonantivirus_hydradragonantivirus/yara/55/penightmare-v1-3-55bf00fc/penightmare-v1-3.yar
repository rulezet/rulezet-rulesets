import "pe"
rule PENightMare_v1_3 {
  strings:
    $a0 = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }

  condition:
    $a0 at pe.entry_point
}