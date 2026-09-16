rule TTP_XOR_QUAD_CurrentVersionRun_0e84 {
  strings:
    $key_0e84 = { 5d eb [2] 79 e5 [2] 52 c9 [2] 7c eb [2] 68 f0 [2] 67 ea [2] 79 f7 [2] 7b f6 [2] 60 f0 [2] 7c f7 [2] 60 d8 }

  condition:
    any of them
}