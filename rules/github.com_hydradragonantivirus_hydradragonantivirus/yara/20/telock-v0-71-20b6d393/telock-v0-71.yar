import "pe"
rule tElock_v0_71 {
  strings:
    $a0 = { 60 E8 ED 10 00 00 C3 83 }

  condition:
    $a0 at pe.entry_point
}