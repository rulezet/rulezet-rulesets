rule TTP_XOR_QUAD_CurrentVersionRun_4d9c {
  strings:
    $key_4d9c = { 1e f3 [2] 3a fd [2] 11 d1 [2] 3f f3 [2] 2b e8 [2] 24 f2 [2] 3a ef [2] 38 ee [2] 23 e8 [2] 3f ef [2] 23 c0 }

  condition:
    any of them
}