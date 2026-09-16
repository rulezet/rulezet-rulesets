rule TTP_XOR_QUAD_CurrentVersionRun_f597 {
  strings:
    $key_f597 = { a6 f8 [2] 82 f6 [2] a9 da [2] 87 f8 [2] 93 e3 [2] 9c f9 [2] 82 e4 [2] 80 e5 [2] 9b e3 [2] 87 e4 [2] 9b cb }

  condition:
    any of them
}