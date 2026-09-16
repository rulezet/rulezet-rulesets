rule TTP_XOR_QUAD_CurrentVersionRun_4984 {
  strings:
    $key_4984 = { 1a eb [2] 3e e5 [2] 15 c9 [2] 3b eb [2] 2f f0 [2] 20 ea [2] 3e f7 [2] 3c f6 [2] 27 f0 [2] 3b f7 [2] 27 d8 }

  condition:
    any of them
}