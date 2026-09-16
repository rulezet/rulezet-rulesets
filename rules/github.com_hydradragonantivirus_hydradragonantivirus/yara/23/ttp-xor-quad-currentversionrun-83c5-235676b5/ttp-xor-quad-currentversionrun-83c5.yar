rule TTP_XOR_QUAD_CurrentVersionRun_83c5 {
  strings:
    $key_83c5 = { d0 aa [2] f4 a4 [2] df 88 [2] f1 aa [2] e5 b1 [2] ea ab [2] f4 b6 [2] f6 b7 [2] ed b1 [2] f1 b6 [2] ed 99 }

  condition:
    any of them
}