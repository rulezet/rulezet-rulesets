rule TTP_XOR_QUAD_CurrentVersionRun_2d96 {
  strings:
    $key_2d96 = { 7e f9 [2] 5a f7 [2] 71 db [2] 5f f9 [2] 4b e2 [2] 44 f8 [2] 5a e5 [2] 58 e4 [2] 43 e2 [2] 5f e5 [2] 43 ca }

  condition:
    any of them
}