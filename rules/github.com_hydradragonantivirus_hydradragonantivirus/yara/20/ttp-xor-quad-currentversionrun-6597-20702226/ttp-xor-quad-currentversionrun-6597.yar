rule TTP_XOR_QUAD_CurrentVersionRun_6597 {
  strings:
    $key_6597 = { 36 f8 [2] 12 f6 [2] 39 da [2] 17 f8 [2] 03 e3 [2] 0c f9 [2] 12 e4 [2] 10 e5 [2] 0b e3 [2] 17 e4 [2] 0b cb }

  condition:
    any of them
}