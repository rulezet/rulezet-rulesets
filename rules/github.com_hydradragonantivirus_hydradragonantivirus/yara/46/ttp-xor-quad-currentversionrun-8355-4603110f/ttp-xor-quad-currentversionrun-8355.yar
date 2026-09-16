rule TTP_XOR_QUAD_CurrentVersionRun_8355 {
  strings:
    $key_8355 = { d0 3a [2] f4 34 [2] df 18 [2] f1 3a [2] e5 21 [2] ea 3b [2] f4 26 [2] f6 27 [2] ed 21 [2] f1 26 [2] ed 09 }

  condition:
    any of them
}