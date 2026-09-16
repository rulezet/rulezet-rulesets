rule TTP_XOR_QUAD_CurrentVersionRun_8457 {
  strings:
    $key_8457 = { d7 38 [2] f3 36 [2] d8 1a [2] f6 38 [2] e2 23 [2] ed 39 [2] f3 24 [2] f1 25 [2] ea 23 [2] f6 24 [2] ea 0b }

  condition:
    any of them
}