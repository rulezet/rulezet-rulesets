rule TTP_XOR_QUAD_CurrentVersionRun_1d96 {
  strings:
    $key_1d96 = { 4e f9 [2] 6a f7 [2] 41 db [2] 6f f9 [2] 7b e2 [2] 74 f8 [2] 6a e5 [2] 68 e4 [2] 73 e2 [2] 6f e5 [2] 73 ca }

  condition:
    any of them
}