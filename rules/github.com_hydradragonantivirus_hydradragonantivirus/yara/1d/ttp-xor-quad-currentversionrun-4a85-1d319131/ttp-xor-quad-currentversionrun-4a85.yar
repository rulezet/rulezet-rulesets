rule TTP_XOR_QUAD_CurrentVersionRun_4a85 {
  strings:
    $key_4a85 = { 19 ea [2] 3d e4 [2] 16 c8 [2] 38 ea [2] 2c f1 [2] 23 eb [2] 3d f6 [2] 3f f7 [2] 24 f1 [2] 38 f6 [2] 24 d9 }

  condition:
    any of them
}