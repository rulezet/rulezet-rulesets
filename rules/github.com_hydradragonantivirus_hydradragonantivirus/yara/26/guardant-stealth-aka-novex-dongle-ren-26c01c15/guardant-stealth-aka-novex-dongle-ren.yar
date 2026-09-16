import "pe"
rule Guardant_Stealth_aka_Novex_Dongle_ren {
  strings:
    $a0 = { 55 8B EC 83 C4 F0 60 E8 51 FF FF FF }

  condition:
    $a0 at pe.entry_point
}