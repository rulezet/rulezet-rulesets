rule TTP_XOR_QUAD_CurrentVersionRun_8187 {
  strings:
    $key_8187 = { d2 e8 [2] f6 e6 [2] dd ca [2] f3 e8 [2] e7 f3 [2] e8 e9 [2] f6 f4 [2] f4 f5 [2] ef f3 [2] f3 f4 [2] ef db }

  condition:
    any of them
}