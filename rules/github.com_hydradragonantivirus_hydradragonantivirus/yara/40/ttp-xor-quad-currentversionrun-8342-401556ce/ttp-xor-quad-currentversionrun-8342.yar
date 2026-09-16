rule TTP_XOR_QUAD_CurrentVersionRun_8342 {
  strings:
    $key_8342 = { d0 2d [2] f4 23 [2] df 0f [2] f1 2d [2] e5 36 [2] ea 2c [2] f4 31 [2] f6 30 [2] ed 36 [2] f1 31 [2] ed 1e }

  condition:
    any of them
}