rule TTP_XOR_QUAD_CurrentVersionRun_8364 {
  strings:
    $key_8364 = { d0 0b [2] f4 05 [2] df 29 [2] f1 0b [2] e5 10 [2] ea 0a [2] f4 17 [2] f6 16 [2] ed 10 [2] f1 17 [2] ed 38 }

  condition:
    any of them
}