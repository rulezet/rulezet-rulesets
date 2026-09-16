rule TTP_XOR_QUAD_CurrentVersionRun_4f9c {
  strings:
    $key_4f9c = { 1c f3 [2] 38 fd [2] 13 d1 [2] 3d f3 [2] 29 e8 [2] 26 f2 [2] 38 ef [2] 3a ee [2] 21 e8 [2] 3d ef [2] 21 c0 }

  condition:
    any of them
}