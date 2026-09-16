rule TTP_XOR_QUAD_CurrentVersionRun_7f98 {
  strings:
    $key_7f98 = { 2c f7 [2] 08 f9 [2] 23 d5 [2] 0d f7 [2] 19 ec [2] 16 f6 [2] 08 eb [2] 0a ea [2] 11 ec [2] 0d eb [2] 11 c4 }

  condition:
    any of them
}