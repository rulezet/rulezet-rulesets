rule TTP_XOR_QUAD_CurrentVersionRun_8359 {
  strings:
    $key_8359 = { d0 36 [2] f4 38 [2] df 14 [2] f1 36 [2] e5 2d [2] ea 37 [2] f4 2a [2] f6 2b [2] ed 2d [2] f1 2a [2] ed 05 }

  condition:
    any of them
}