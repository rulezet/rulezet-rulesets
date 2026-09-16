import "pe"
rule Vx__Kuku_448 {
  strings:
    $a0 = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }

  condition:
    $a0 at pe.entry_point
}