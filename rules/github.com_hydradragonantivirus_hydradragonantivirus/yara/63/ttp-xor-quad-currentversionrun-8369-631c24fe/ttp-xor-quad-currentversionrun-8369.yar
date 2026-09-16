rule TTP_XOR_QUAD_CurrentVersionRun_8369 {
  strings:
    $key_8369 = { d0 06 [2] f4 08 [2] df 24 [2] f1 06 [2] e5 1d [2] ea 07 [2] f4 1a [2] f6 1b [2] ed 1d [2] f1 1a [2] ed 35 }

  condition:
    any of them
}