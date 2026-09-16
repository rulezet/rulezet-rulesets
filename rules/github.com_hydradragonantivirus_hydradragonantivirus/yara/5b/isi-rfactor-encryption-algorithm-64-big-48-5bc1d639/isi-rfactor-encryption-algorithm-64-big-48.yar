rule ISI_rFactor_encryption_algorithm__64_big_48_ {
  strings:
    $a0 = { e5 6f 8a a2 ed 82 6f aa 2f 77 7c f9 c7 00 31 d8 12 b4 2c 08 2f 77 53 a9 e5 c4 f0 ac a2 18 13 8d ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff }

  condition:
    $a0
}