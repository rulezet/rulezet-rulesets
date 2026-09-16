rule TTP_XOR_QUAD_CurrentVersionRun_8442 {
  strings:
    $key_8442 = { d7 2d [2] f3 23 [2] d8 0f [2] f6 2d [2] e2 36 [2] ed 2c [2] f3 31 [2] f1 30 [2] ea 36 [2] f6 31 [2] ea 1e }

  condition:
    any of them
}