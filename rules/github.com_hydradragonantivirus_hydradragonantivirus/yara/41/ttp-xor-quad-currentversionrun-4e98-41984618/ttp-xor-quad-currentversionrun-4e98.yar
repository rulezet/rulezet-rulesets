rule TTP_XOR_QUAD_CurrentVersionRun_4e98 {
  strings:
    $key_4e98 = { 1d f7 [2] 39 f9 [2] 12 d5 [2] 3c f7 [2] 28 ec [2] 27 f6 [2] 39 eb [2] 3b ea [2] 20 ec [2] 3c eb [2] 20 c4 }

  condition:
    any of them
}