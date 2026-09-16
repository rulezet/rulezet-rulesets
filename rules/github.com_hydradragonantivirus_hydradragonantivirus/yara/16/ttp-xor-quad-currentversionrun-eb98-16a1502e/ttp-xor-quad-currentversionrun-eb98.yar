rule TTP_XOR_QUAD_CurrentVersionRun_eb98 {
  strings:
    $key_eb98 = { b8 f7 [2] 9c f9 [2] b7 d5 [2] 99 f7 [2] 8d ec [2] 82 f6 [2] 9c eb [2] 9e ea [2] 85 ec [2] 99 eb [2] 85 c4 }

  condition:
    any of them
}