rule TTP_XOR_QUAD_CurrentVersionRun_788b {
  strings:
    $key_788b = { 2b e4 [2] 0f ea [2] 24 c6 [2] 0a e4 [2] 1e ff [2] 11 e5 [2] 0f f8 [2] 0d f9 [2] 16 ff [2] 0a f8 [2] 16 d7 }

  condition:
    any of them
}