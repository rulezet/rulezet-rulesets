rule TTP_XOR_QUAD_CurrentVersionRun_5a97 {
  strings:
    $key_5a97 = { 09 f8 [2] 2d f6 [2] 06 da [2] 28 f8 [2] 3c e3 [2] 33 f9 [2] 2d e4 [2] 2f e5 [2] 34 e3 [2] 28 e4 [2] 34 cb }

  condition:
    any of them
}