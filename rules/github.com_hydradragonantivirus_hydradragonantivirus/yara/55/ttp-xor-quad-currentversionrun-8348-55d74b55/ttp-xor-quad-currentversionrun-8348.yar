rule TTP_XOR_QUAD_CurrentVersionRun_8348 {
  strings:
    $key_8348 = { d0 27 [2] f4 29 [2] df 05 [2] f1 27 [2] e5 3c [2] ea 26 [2] f4 3b [2] f6 3a [2] ed 3c [2] f1 3b [2] ed 14 }

  condition:
    any of them
}