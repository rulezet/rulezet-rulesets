rule TTP_XOR_QUAD_CurrentVersionRun_2d9d {
  strings:
    $key_2d9d = { 7e f2 [2] 5a fc [2] 71 d0 [2] 5f f2 [2] 4b e9 [2] 44 f3 [2] 5a ee [2] 58 ef [2] 43 e9 [2] 5f ee [2] 43 c1 }

  condition:
    any of them
}