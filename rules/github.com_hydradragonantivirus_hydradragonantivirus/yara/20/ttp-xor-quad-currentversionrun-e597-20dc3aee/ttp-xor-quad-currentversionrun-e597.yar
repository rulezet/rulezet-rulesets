rule TTP_XOR_QUAD_CurrentVersionRun_e597 {
  strings:
    $key_e597 = { b6 f8 [2] 92 f6 [2] b9 da [2] 97 f8 [2] 83 e3 [2] 8c f9 [2] 92 e4 [2] 90 e5 [2] 8b e3 [2] 97 e4 [2] 8b cb }

  condition:
    any of them
}