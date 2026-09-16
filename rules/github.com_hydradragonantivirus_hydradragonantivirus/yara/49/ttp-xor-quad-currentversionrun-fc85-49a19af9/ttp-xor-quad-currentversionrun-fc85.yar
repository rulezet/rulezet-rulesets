rule TTP_XOR_QUAD_CurrentVersionRun_fc85 {
  strings:
    $key_fc85 = { af ea [2] 8b e4 [2] a0 c8 [2] 8e ea [2] 9a f1 [2] 95 eb [2] 8b f6 [2] 89 f7 [2] 92 f1 [2] 8e f6 [2] 92 d9 }

  condition:
    any of them
}