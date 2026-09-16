rule TTP_XOR_QUAD_CurrentVersionRun_8368 {
  strings:
    $key_8368 = { d0 07 [2] f4 09 [2] df 25 [2] f1 07 [2] e5 1c [2] ea 06 [2] f4 1b [2] f6 1a [2] ed 1c [2] f1 1b [2] ed 34 }

  condition:
    any of them
}