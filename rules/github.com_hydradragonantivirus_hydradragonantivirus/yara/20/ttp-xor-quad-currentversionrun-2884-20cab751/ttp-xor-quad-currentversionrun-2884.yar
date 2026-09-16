rule TTP_XOR_QUAD_CurrentVersionRun_2884 {
  strings:
    $key_2884 = { 7b eb [2] 5f e5 [2] 74 c9 [2] 5a eb [2] 4e f0 [2] 41 ea [2] 5f f7 [2] 5d f6 [2] 46 f0 [2] 5a f7 [2] 46 d8 }

  condition:
    any of them
}