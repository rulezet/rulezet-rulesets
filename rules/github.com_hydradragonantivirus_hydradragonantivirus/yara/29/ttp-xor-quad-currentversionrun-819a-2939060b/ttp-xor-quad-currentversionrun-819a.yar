rule TTP_XOR_QUAD_CurrentVersionRun_819a {
  strings:
    $key_819a = { d2 f5 [2] f6 fb [2] dd d7 [2] f3 f5 [2] e7 ee [2] e8 f4 [2] f6 e9 [2] f4 e8 [2] ef ee [2] f3 e9 [2] ef c6 }

  condition:
    any of them
}