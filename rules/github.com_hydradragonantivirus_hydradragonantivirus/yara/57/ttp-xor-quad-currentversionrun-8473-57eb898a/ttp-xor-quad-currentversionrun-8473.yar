rule TTP_XOR_QUAD_CurrentVersionRun_8473 {
  strings:
    $key_8473 = { d7 1c [2] f3 12 [2] d8 3e [2] f6 1c [2] e2 07 [2] ed 1d [2] f3 00 [2] f1 01 [2] ea 07 [2] f6 00 [2] ea 2f }

  condition:
    any of them
}