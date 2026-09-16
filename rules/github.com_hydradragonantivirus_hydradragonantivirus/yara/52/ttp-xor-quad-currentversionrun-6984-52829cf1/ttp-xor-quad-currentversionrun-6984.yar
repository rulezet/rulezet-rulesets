rule TTP_XOR_QUAD_CurrentVersionRun_6984 {
  strings:
    $key_6984 = { 3a eb [2] 1e e5 [2] 35 c9 [2] 1b eb [2] 0f f0 [2] 00 ea [2] 1e f7 [2] 1c f6 [2] 07 f0 [2] 1b f7 [2] 07 d8 }

  condition:
    any of them
}