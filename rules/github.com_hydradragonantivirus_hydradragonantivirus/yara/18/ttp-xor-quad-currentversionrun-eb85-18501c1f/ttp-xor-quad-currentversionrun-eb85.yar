rule TTP_XOR_QUAD_CurrentVersionRun_eb85 {
  strings:
    $key_eb85 = { b8 ea [2] 9c e4 [2] b7 c8 [2] 99 ea [2] 8d f1 [2] 82 eb [2] 9c f6 [2] 9e f7 [2] 85 f1 [2] 99 f6 [2] 85 d9 }

  condition:
    any of them
}