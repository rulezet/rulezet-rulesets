rule TTP_XOR_QUAD_CurrentVersionRun_4e97 {
  strings:
    $key_4e97 = { 1d f8 [2] 39 f6 [2] 12 da [2] 3c f8 [2] 28 e3 [2] 27 f9 [2] 39 e4 [2] 3b e5 [2] 20 e3 [2] 3c e4 [2] 20 cb }

  condition:
    any of them
}