rule TTP_XOR_QUAD_CurrentVersionRun_8447 {
  strings:
    $key_8447 = { d7 28 [2] f3 26 [2] d8 0a [2] f6 28 [2] e2 33 [2] ed 29 [2] f3 34 [2] f1 35 [2] ea 33 [2] f6 34 [2] ea 1b }

  condition:
    any of them
}