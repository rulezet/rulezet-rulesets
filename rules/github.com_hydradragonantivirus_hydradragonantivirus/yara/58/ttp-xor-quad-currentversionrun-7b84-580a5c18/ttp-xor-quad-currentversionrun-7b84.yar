rule TTP_XOR_QUAD_CurrentVersionRun_7b84 {
  strings:
    $key_7b84 = { 28 eb [2] 0c e5 [2] 27 c9 [2] 09 eb [2] 1d f0 [2] 12 ea [2] 0c f7 [2] 0e f6 [2] 15 f0 [2] 09 f7 [2] 15 d8 }

  condition:
    any of them
}