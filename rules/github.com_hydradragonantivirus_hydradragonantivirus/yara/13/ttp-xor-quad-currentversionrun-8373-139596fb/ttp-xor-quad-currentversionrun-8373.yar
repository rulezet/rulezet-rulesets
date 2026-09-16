rule TTP_XOR_QUAD_CurrentVersionRun_8373 {
  strings:
    $key_8373 = { d0 1c [2] f4 12 [2] df 3e [2] f1 1c [2] e5 07 [2] ea 1d [2] f4 00 [2] f6 01 [2] ed 07 [2] f1 00 [2] ed 2f }

  condition:
    any of them
}