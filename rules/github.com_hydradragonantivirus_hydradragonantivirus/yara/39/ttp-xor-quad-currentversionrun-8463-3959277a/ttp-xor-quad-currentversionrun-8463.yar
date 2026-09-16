rule TTP_XOR_QUAD_CurrentVersionRun_8463 {
  strings:
    $key_8463 = { d7 0c [2] f3 02 [2] d8 2e [2] f6 0c [2] e2 17 [2] ed 0d [2] f3 10 [2] f1 11 [2] ea 17 [2] f6 10 [2] ea 3f }

  condition:
    any of them
}