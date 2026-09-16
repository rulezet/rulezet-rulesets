rule TTP_XOR_QUAD_CurrentVersionRun_1497 {
  strings:
    $key_1497 = { 47 f8 [2] 63 f6 [2] 48 da [2] 66 f8 [2] 72 e3 [2] 7d f9 [2] 63 e4 [2] 61 e5 [2] 7a e3 [2] 66 e4 [2] 7a cb }

  condition:
    any of them
}