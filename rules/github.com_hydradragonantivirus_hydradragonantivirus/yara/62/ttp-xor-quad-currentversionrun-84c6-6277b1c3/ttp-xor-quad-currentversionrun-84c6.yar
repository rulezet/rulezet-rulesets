rule TTP_XOR_QUAD_CurrentVersionRun_84c6 {
  strings:
    $key_84c6 = { d7 a9 [2] f3 a7 [2] d8 8b [2] f6 a9 [2] e2 b2 [2] ed a8 [2] f3 b5 [2] f1 b4 [2] ea b2 [2] f6 b5 [2] ea 9a }

  condition:
    any of them
}