rule TTP_XOR_QUAD_CurrentVersionRun_088b {
  strings:
    $key_088b = { 5b e4 [2] 7f ea [2] 54 c6 [2] 7a e4 [2] 6e ff [2] 61 e5 [2] 7f f8 [2] 7d f9 [2] 66 ff [2] 7a f8 [2] 66 d7 }

  condition:
    any of them
}