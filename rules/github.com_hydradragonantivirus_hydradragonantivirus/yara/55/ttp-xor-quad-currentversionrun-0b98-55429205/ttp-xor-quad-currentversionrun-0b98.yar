rule TTP_XOR_QUAD_CurrentVersionRun_0b98 {
  strings:
    $key_0b98 = { 58 f7 [2] 7c f9 [2] 57 d5 [2] 79 f7 [2] 6d ec [2] 62 f6 [2] 7c eb [2] 7e ea [2] 65 ec [2] 79 eb [2] 65 c4 }

  condition:
    any of them
}