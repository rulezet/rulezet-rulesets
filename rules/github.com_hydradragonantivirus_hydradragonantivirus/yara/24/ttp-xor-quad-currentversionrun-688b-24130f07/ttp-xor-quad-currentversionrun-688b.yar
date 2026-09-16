rule TTP_XOR_QUAD_CurrentVersionRun_688b {
  strings:
    $key_688b = { 3b e4 [2] 1f ea [2] 34 c6 [2] 1a e4 [2] 0e ff [2] 01 e5 [2] 1f f8 [2] 1d f9 [2] 06 ff [2] 1a f8 [2] 06 d7 }

  condition:
    any of them
}