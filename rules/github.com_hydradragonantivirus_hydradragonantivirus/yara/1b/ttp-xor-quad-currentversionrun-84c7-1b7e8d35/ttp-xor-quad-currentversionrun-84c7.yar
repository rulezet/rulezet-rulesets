rule TTP_XOR_QUAD_CurrentVersionRun_84c7 {
  strings:
    $key_84c7 = { d7 a8 [2] f3 a6 [2] d8 8a [2] f6 a8 [2] e2 b3 [2] ed a9 [2] f3 b4 [2] f1 b5 [2] ea b3 [2] f6 b4 [2] ea 9b }

  condition:
    any of them
}