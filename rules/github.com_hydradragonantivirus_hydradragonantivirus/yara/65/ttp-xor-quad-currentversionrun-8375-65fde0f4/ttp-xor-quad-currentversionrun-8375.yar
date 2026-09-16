rule TTP_XOR_QUAD_CurrentVersionRun_8375 {
  strings:
    $key_8375 = { d0 1a [2] f4 14 [2] df 38 [2] f1 1a [2] e5 01 [2] ea 1b [2] f4 06 [2] f6 07 [2] ed 01 [2] f1 06 [2] ed 29 }

  condition:
    any of them
}