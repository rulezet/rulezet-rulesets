rule TTP_XOR_QUAD_CurrentVersionRun_2597 {
  strings:
    $key_2597 = { 76 f8 [2] 52 f6 [2] 79 da [2] 57 f8 [2] 43 e3 [2] 4c f9 [2] 52 e4 [2] 50 e5 [2] 4b e3 [2] 57 e4 [2] 4b cb }

  condition:
    any of them
}