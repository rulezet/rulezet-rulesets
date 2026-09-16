rule TTP_XOR_QUAD_CurrentVersionRun_8338 {
  strings:
    $key_8338 = { d0 57 [2] f4 59 [2] df 75 [2] f1 57 [2] e5 4c [2] ea 56 [2] f4 4b [2] f6 4a [2] ed 4c [2] f1 4b [2] ed 64 }

  condition:
    any of them
}