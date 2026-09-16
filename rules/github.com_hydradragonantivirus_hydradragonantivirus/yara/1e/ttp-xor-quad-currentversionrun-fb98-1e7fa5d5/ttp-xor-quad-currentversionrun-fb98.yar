rule TTP_XOR_QUAD_CurrentVersionRun_fb98 {
  strings:
    $key_fb98 = { a8 f7 [2] 8c f9 [2] a7 d5 [2] 89 f7 [2] 9d ec [2] 92 f6 [2] 8c eb [2] 8e ea [2] 95 ec [2] 89 eb [2] 95 c4 }

  condition:
    any of them
}