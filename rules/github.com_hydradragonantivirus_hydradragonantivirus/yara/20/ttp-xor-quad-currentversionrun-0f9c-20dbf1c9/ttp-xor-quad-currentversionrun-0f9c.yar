rule TTP_XOR_QUAD_CurrentVersionRun_0f9c {
  strings:
    $key_0f9c = { 5c f3 [2] 78 fd [2] 53 d1 [2] 7d f3 [2] 69 e8 [2] 66 f2 [2] 78 ef [2] 7a ee [2] 61 e8 [2] 7d ef [2] 61 c0 }

  condition:
    any of them
}