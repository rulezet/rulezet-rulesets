rule TTP_XOR_QUAD_CurrentVersionRun_0f98 {
  strings:
    $key_0f98 = { 5c f7 [2] 78 f9 [2] 53 d5 [2] 7d f7 [2] 69 ec [2] 66 f6 [2] 78 eb [2] 7a ea [2] 61 ec [2] 7d eb [2] 61 c4 }

  condition:
    any of them
}