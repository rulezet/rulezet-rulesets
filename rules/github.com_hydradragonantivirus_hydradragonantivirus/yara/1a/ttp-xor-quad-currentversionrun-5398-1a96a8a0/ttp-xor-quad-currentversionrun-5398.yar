rule TTP_XOR_QUAD_CurrentVersionRun_5398 {
  strings:
    $key_5398 = { 00 f7 [2] 24 f9 [2] 0f d5 [2] 21 f7 [2] 35 ec [2] 3a f6 [2] 24 eb [2] 26 ea [2] 3d ec [2] 21 eb [2] 3d c4 }

  condition:
    any of them
}