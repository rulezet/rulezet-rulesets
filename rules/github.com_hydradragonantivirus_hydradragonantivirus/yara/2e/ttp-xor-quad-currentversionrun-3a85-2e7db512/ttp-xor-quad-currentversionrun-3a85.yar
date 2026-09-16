rule TTP_XOR_QUAD_CurrentVersionRun_3a85 {
  strings:
    $key_3a85 = { 69 ea [2] 4d e4 [2] 66 c8 [2] 48 ea [2] 5c f1 [2] 53 eb [2] 4d f6 [2] 4f f7 [2] 54 f1 [2] 48 f6 [2] 54 d9 }

  condition:
    any of them
}