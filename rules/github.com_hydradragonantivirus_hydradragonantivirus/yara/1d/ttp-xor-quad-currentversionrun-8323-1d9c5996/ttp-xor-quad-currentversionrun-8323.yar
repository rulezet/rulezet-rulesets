rule TTP_XOR_QUAD_CurrentVersionRun_8323 {
  strings:
    $key_8323 = { d0 4c [2] f4 42 [2] df 6e [2] f1 4c [2] e5 57 [2] ea 4d [2] f4 50 [2] f6 51 [2] ed 57 [2] f1 50 [2] ed 7f }

  condition:
    any of them
}