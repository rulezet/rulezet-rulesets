rule TTP_XOR_QUAD_CurrentVersionRun_83e8 {
  strings:
    $key_83e8 = { d0 87 [2] f4 89 [2] df a5 [2] f1 87 [2] e5 9c [2] ea 86 [2] f4 9b [2] f6 9a [2] ed 9c [2] f1 9b [2] ed b4 }

  condition:
    any of them
}