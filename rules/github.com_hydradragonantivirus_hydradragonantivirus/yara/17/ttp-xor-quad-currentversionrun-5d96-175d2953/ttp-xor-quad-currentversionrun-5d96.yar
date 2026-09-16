rule TTP_XOR_QUAD_CurrentVersionRun_5d96 {
  strings:
    $key_5d96 = { 0e f9 [2] 2a f7 [2] 01 db [2] 2f f9 [2] 3b e2 [2] 34 f8 [2] 2a e5 [2] 28 e4 [2] 33 e2 [2] 2f e5 [2] 33 ca }

  condition:
    any of them
}