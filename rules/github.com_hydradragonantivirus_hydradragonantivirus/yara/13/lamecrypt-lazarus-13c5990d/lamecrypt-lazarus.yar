import "pe"
rule LameCrypt____LaZaRus {
  strings:
    $a0 = { 60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 ?? ?? 40 00 FF E0 }

  condition:
    $a0 at pe.entry_point
}