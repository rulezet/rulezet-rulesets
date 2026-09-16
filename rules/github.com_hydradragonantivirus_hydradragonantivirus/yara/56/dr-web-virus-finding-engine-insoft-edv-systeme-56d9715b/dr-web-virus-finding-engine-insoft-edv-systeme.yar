import "pe"
rule Dr_Web_Virus_Finding_Engine____InSoft_EDV_Systeme {
  strings:
    $a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }

  condition:
    $a0 at pe.entry_point
}