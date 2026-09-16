rule TTP_XOR_QUAD_CurrentVersionRun_8363 {
  strings:
    $key_8363 = { d0 0c [2] f4 02 [2] df 2e [2] f1 0c [2] e5 17 [2] ea 0d [2] f4 10 [2] f6 11 [2] ed 17 [2] f1 10 [2] ed 3f }

  condition:
    any of them
}