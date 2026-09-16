rule TTP_XOR_QUAD_CurrentVersionRun_7497 {
  strings:
    $key_7497 = { 27 f8 [2] 03 f6 [2] 28 da [2] 06 f8 [2] 12 e3 [2] 1d f9 [2] 03 e4 [2] 01 e5 [2] 1a e3 [2] 06 e4 [2] 1a cb }

  condition:
    any of them
}