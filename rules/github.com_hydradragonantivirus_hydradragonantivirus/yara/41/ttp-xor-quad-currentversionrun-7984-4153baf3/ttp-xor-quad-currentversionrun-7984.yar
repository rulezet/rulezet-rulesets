rule TTP_XOR_QUAD_CurrentVersionRun_7984 {
  strings:
    $key_7984 = { 2a eb [2] 0e e5 [2] 25 c9 [2] 0b eb [2] 1f f0 [2] 10 ea [2] 0e f7 [2] 0c f6 [2] 17 f0 [2] 0b f7 [2] 17 d8 }

  condition:
    any of them
}