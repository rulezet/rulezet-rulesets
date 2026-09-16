rule TTP_XOR_QUAD_CurrentVersionRun_2f98 {
  strings:
    $key_2f98 = { 7c f7 [2] 58 f9 [2] 73 d5 [2] 5d f7 [2] 49 ec [2] 46 f6 [2] 58 eb [2] 5a ea [2] 41 ec [2] 5d eb [2] 41 c4 }

  condition:
    any of them
}