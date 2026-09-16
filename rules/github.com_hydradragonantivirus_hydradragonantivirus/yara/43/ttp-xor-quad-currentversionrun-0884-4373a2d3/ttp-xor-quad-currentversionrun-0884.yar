rule TTP_XOR_QUAD_CurrentVersionRun_0884 {
  strings:
    $key_0884 = { 5b eb [2] 7f e5 [2] 54 c9 [2] 7a eb [2] 6e f0 [2] 61 ea [2] 7f f7 [2] 7d f6 [2] 66 f0 [2] 7a f7 [2] 66 d8 }

  condition:
    any of them
}