rule TTP_XOR_QUAD_CurrentVersionRun_4f97 {
  strings:
    $key_4f97 = { 1c f8 [2] 38 f6 [2] 13 da [2] 3d f8 [2] 29 e3 [2] 26 f9 [2] 38 e4 [2] 3a e5 [2] 21 e3 [2] 3d e4 [2] 21 cb }

  condition:
    any of them
}