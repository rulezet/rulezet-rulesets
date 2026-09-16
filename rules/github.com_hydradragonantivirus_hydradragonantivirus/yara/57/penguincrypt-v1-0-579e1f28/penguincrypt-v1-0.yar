import "pe"
rule PEnguinCrypt_v1_0 {
  strings:
    $a0 = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }

  condition:
    $a0 at pe.entry_point
}