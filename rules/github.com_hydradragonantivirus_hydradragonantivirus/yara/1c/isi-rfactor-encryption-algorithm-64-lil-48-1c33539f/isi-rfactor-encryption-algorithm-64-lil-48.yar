rule ISI_rFactor_encryption_algorithm__64_lil_48_ {
  strings:
    $a0 = { aa 6f 82 ed a2 8a 6f e5 d8 31 00 c7 f9 7c 77 2f a9 53 77 2f 08 2c b4 12 8d 13 18 a2 ac f0 c4 e5 00 00 00 00 00 00 00 ff ff 00 00 00 00 00 00 00 }

  condition:
    $a0
}