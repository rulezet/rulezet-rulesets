rule TTP_XOR_QUAD_CurrentVersionRun_0d9c {
  strings:
    $key_0d9c = { 5e f3 [2] 7a fd [2] 51 d1 [2] 7f f3 [2] 6b e8 [2] 64 f2 [2] 7a ef [2] 78 ee [2] 63 e8 [2] 7f ef [2] 63 c0 }

  condition:
    any of them
}