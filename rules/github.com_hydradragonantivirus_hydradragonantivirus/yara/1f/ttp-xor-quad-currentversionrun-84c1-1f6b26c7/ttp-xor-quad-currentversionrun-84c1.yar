rule TTP_XOR_QUAD_CurrentVersionRun_84c1 {
  strings:
    $key_84c1 = { d7 ae [2] f3 a0 [2] d8 8c [2] f6 ae [2] e2 b5 [2] ed af [2] f3 b2 [2] f1 b3 [2] ea b5 [2] f6 b2 [2] ea 9d }

  condition:
    any of them
}