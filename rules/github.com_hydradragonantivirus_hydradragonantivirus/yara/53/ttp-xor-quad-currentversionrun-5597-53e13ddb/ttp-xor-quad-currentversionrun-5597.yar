rule TTP_XOR_QUAD_CurrentVersionRun_5597 {
  strings:
    $key_5597 = { 06 f8 [2] 22 f6 [2] 09 da [2] 27 f8 [2] 33 e3 [2] 3c f9 [2] 22 e4 [2] 20 e5 [2] 3b e3 [2] 27 e4 [2] 3b cb }

  condition:
    any of them
}