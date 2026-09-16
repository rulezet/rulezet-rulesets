rule TTP_XOR_QUAD_CurrentVersionRun_6e84 {
  strings:
    $key_6e84 = { 3d eb [2] 19 e5 [2] 32 c9 [2] 1c eb [2] 08 f0 [2] 07 ea [2] 19 f7 [2] 1b f6 [2] 00 f0 [2] 1c f7 [2] 00 d8 }

  condition:
    any of them
}