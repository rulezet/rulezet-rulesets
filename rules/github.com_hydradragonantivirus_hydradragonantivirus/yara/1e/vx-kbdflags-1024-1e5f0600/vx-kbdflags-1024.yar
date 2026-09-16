import "pe"
rule Vx__KBDflags_1024 {
  strings:
    $a0 = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }

  condition:
    $a0 at pe.entry_point
}