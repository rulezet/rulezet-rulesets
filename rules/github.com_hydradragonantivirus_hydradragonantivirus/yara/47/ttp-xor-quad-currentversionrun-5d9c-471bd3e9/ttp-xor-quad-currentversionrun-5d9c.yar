rule TTP_XOR_QUAD_CurrentVersionRun_5d9c {
  strings:
    $key_5d9c = { 0e f3 [2] 2a fd [2] 01 d1 [2] 2f f3 [2] 3b e8 [2] 34 f2 [2] 2a ef [2] 28 ee [2] 33 e8 [2] 2f ef [2] 33 c0 }

  condition:
    any of them
}