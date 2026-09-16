rule TTP_XOR_QUAD_CurrentVersionRun_8477 {
  strings:
    $key_8477 = { d7 18 [2] f3 16 [2] d8 3a [2] f6 18 [2] e2 03 [2] ed 19 [2] f3 04 [2] f1 05 [2] ea 03 [2] f6 04 [2] ea 2b }

  condition:
    any of them
}