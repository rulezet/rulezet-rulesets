rule TTP_XOR_QUAD_CurrentVersionRun_5397 {
  strings:
    $key_5397 = { 00 f8 [2] 24 f6 [2] 0f da [2] 21 f8 [2] 35 e3 [2] 3a f9 [2] 24 e4 [2] 26 e5 [2] 3d e3 [2] 21 e4 [2] 3d cb }

  condition:
    any of them
}