rule TTP_XOR_QUAD_CurrentVersionRun_8376 {
  strings:
    $key_8376 = { d0 19 [2] f4 17 [2] df 3b [2] f1 19 [2] e5 02 [2] ea 18 [2] f4 05 [2] f6 04 [2] ed 02 [2] f1 05 [2] ed 2a }

  condition:
    any of them
}