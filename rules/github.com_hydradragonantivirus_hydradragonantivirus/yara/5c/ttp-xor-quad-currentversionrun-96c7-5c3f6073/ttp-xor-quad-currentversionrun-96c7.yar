rule TTP_XOR_QUAD_CurrentVersionRun_96c7 {
  strings:
    $key_96c7 = { c5 a8 [2] e1 a6 [2] ca 8a [2] e4 a8 [2] f0 b3 [2] ff a9 [2] e1 b4 [2] e3 b5 [2] f8 b3 [2] e4 b4 [2] f8 9b }

  condition:
    any of them
}