rule TTP_XOR_QUAD_CurrentVersionRun_8436 {
  strings:
    $key_8436 = { d7 59 [2] f3 57 [2] d8 7b [2] f6 59 [2] e2 42 [2] ed 58 [2] f3 45 [2] f1 44 [2] ea 42 [2] f6 45 [2] ea 6a }

  condition:
    any of them
}