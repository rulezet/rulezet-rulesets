rule TTP_XOR_QUAD_CurrentVersionRun_7e84 {
  strings:
    $key_7e84 = { 2d eb [2] 09 e5 [2] 22 c9 [2] 0c eb [2] 18 f0 [2] 17 ea [2] 09 f7 [2] 0b f6 [2] 10 f0 [2] 0c f7 [2] 10 d8 }

  condition:
    any of them
}