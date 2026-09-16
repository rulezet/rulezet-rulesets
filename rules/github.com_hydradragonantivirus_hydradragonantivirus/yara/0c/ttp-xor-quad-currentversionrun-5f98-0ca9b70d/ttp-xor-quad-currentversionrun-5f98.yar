rule TTP_XOR_QUAD_CurrentVersionRun_5f98 {
  strings:
    $key_5f98 = { 0c f7 [2] 28 f9 [2] 03 d5 [2] 2d f7 [2] 39 ec [2] 36 f6 [2] 28 eb [2] 2a ea [2] 31 ec [2] 2d eb [2] 31 c4 }

  condition:
    any of them
}