import "pe"
rule Vx__Igor {
  strings:
    $a0 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }

  condition:
    $a0 at pe.entry_point
}