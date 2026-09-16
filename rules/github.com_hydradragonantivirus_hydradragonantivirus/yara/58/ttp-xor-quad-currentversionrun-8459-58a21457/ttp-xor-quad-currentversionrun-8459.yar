rule TTP_XOR_QUAD_CurrentVersionRun_8459 {
  strings:
    $key_8459 = { d7 36 [2] f3 38 [2] d8 14 [2] f6 36 [2] e2 2d [2] ed 37 [2] f3 2a [2] f1 2b [2] ea 2d [2] f6 2a [2] ea 05 }

  condition:
    any of them
}