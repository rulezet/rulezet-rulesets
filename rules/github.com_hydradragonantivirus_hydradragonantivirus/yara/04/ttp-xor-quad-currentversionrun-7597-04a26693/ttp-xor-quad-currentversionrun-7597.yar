rule TTP_XOR_QUAD_CurrentVersionRun_7597 {
  strings:
    $key_7597 = { 26 f8 [2] 02 f6 [2] 29 da [2] 07 f8 [2] 13 e3 [2] 1c f9 [2] 02 e4 [2] 00 e5 [2] 1b e3 [2] 07 e4 [2] 1b cb }

  condition:
    any of them
}