rule TTP_XOR_QUAD_CurrentVersionRun_2d97 {
  strings:
    $key_2d97 = { 7e f8 [2] 5a f6 [2] 71 da [2] 5f f8 [2] 4b e3 [2] 44 f9 [2] 5a e4 [2] 58 e5 [2] 43 e3 [2] 5f e4 [2] 43 cb }

  condition:
    any of them
}