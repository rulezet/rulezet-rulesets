rule TTP_XOR_QUAD_CurrentVersionRun_83e4 {
  strings:
    $key_83e4 = { d0 8b [2] f4 85 [2] df a9 [2] f1 8b [2] e5 90 [2] ea 8a [2] f4 97 [2] f6 96 [2] ed 90 [2] f1 97 [2] ed b8 }

  condition:
    any of them
}