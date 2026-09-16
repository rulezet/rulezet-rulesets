rule TTP_XOR_QUAD_CurrentVersionRun_7b98 {
  strings:
    $key_7b98 = { 28 f7 [2] 0c f9 [2] 27 d5 [2] 09 f7 [2] 1d ec [2] 12 f6 [2] 0c eb [2] 0e ea [2] 15 ec [2] 09 eb [2] 15 c4 }

  condition:
    any of them
}