rule TTP_XOR_QUAD_CurrentVersionRun_459d {
  strings:
    $key_459d = { 16 f2 [2] 32 fc [2] 19 d0 [2] 37 f2 [2] 23 e9 [2] 2c f3 [2] 32 ee [2] 30 ef [2] 2b e9 [2] 37 ee [2] 2b c1 }

  condition:
    any of them
}