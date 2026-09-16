rule TTP_XOR_QUAD_CurrentVersionRun_8377 {
  strings:
    $key_8377 = { d0 18 [2] f4 16 [2] df 3a [2] f1 18 [2] e5 03 [2] ea 19 [2] f4 04 [2] f6 05 [2] ed 03 [2] f1 04 [2] ed 2b }

  condition:
    any of them
}