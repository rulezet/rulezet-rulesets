rule TTP_XOR_QUAD_CurrentVersionRun_6d96 {
  strings:
    $key_6d96 = { 3e f9 [2] 1a f7 [2] 31 db [2] 1f f9 [2] 0b e2 [2] 04 f8 [2] 1a e5 [2] 18 e4 [2] 03 e2 [2] 1f e5 [2] 03 ca }

  condition:
    any of them
}