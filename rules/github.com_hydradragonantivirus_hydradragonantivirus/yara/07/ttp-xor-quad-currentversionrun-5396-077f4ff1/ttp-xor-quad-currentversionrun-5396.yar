rule TTP_XOR_QUAD_CurrentVersionRun_5396 {
  strings:
    $key_5396 = { 00 f9 [2] 24 f7 [2] 0f db [2] 21 f9 [2] 35 e2 [2] 3a f8 [2] 24 e5 [2] 26 e4 [2] 3d e2 [2] 21 e5 [2] 3d ca }

  condition:
    any of them
}