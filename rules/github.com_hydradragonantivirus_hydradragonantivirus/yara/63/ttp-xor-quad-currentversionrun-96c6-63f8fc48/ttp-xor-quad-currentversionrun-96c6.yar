rule TTP_XOR_QUAD_CurrentVersionRun_96c6 {
  strings:
    $key_96c6 = { c5 a9 [2] e1 a7 [2] ca 8b [2] e4 a9 [2] f0 b2 [2] ff a8 [2] e1 b5 [2] e3 b4 [2] f8 b2 [2] e4 b5 [2] f8 9a }

  condition:
    any of them
}