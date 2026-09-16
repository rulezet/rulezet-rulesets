rule TTP_XOR_QUAD_CurrentVersionRun_869a {
  strings:
    $key_869a = { d5 f5 [2] f1 fb [2] da d7 [2] f4 f5 [2] e0 ee [2] ef f4 [2] f1 e9 [2] f3 e8 [2] e8 ee [2] f4 e9 [2] e8 c6 }

  condition:
    any of them
}