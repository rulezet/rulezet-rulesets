rule TTP_XOR_QUAD_CurrentVersionRun_3b98 {
  strings:
    $key_3b98 = { 68 f7 [2] 4c f9 [2] 67 d5 [2] 49 f7 [2] 5d ec [2] 52 f6 [2] 4c eb [2] 4e ea [2] 55 ec [2] 49 eb [2] 55 c4 }

  condition:
    any of them
}