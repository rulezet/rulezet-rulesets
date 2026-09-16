rule TTP_XOR_QUAD_CurrentVersionRun_5f97 {
  strings:
    $key_5f97 = { 0c f8 [2] 28 f6 [2] 03 da [2] 2d f8 [2] 39 e3 [2] 36 f9 [2] 28 e4 [2] 2a e5 [2] 31 e3 [2] 2d e4 [2] 31 cb }

  condition:
    any of them
}