rule TTP_XOR_QUAD_CurrentVersionRun_7f9c {
  strings:
    $key_7f9c = { 2c f3 [2] 08 fd [2] 23 d1 [2] 0d f3 [2] 19 e8 [2] 16 f2 [2] 08 ef [2] 0a ee [2] 11 e8 [2] 0d ef [2] 11 c0 }

  condition:
    any of them
}