rule TTP_XOR_QUAD_CurrentVersionRun_1884 {
  strings:
    $key_1884 = { 4b eb [2] 6f e5 [2] 44 c9 [2] 6a eb [2] 7e f0 [2] 71 ea [2] 6f f7 [2] 6d f6 [2] 76 f0 [2] 6a f7 [2] 76 d8 }

  condition:
    any of them
}