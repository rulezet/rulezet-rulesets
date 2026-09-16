rule TTP_XOR_QUAD_CurrentVersionRun_1f97 {
  strings:
    $key_1f97 = { 4c f8 [2] 68 f6 [2] 43 da [2] 6d f8 [2] 79 e3 [2] 76 f9 [2] 68 e4 [2] 6a e5 [2] 71 e3 [2] 6d e4 [2] 71 cb }

  condition:
    any of them
}