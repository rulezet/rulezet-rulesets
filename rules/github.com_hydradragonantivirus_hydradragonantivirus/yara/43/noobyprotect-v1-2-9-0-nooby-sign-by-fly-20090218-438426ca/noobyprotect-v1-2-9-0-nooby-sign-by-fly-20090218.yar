import "pe"
rule NoobyProtect_V1_2_9_0____Nooby_____Sign_By_fly___20090218 {
  strings:
    $a0 = { E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 32 2E 39 2E 30 }

  condition:
    $a0 at pe.entry_point
}