rule TTP_XOR_QUAD_CurrentVersionRun_0497 {
  strings:
    $key_0497 = { 57 f8 [2] 73 f6 [2] 58 da [2] 76 f8 [2] 62 e3 [2] 6d f9 [2] 73 e4 [2] 71 e5 [2] 6a e3 [2] 76 e4 [2] 6a cb }

  condition:
    any of them
}