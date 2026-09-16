rule TTP_XOR_QUAD_CurrentVersionRun_fc84 {
  strings:
    $key_fc84 = { af eb [2] 8b e5 [2] a0 c9 [2] 8e eb [2] 9a f0 [2] 95 ea [2] 8b f7 [2] 89 f6 [2] 92 f0 [2] 8e f7 [2] 92 d8 }

  condition:
    any of them
}