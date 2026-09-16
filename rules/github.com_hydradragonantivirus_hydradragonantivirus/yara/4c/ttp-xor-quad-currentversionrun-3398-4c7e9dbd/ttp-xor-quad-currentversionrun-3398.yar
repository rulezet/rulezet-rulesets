rule TTP_XOR_QUAD_CurrentVersionRun_3398 {
  strings:
    $key_3398 = { 60 f7 [2] 44 f9 [2] 6f d5 [2] 41 f7 [2] 55 ec [2] 5a f6 [2] 44 eb [2] 46 ea [2] 5d ec [2] 41 eb [2] 5d c4 }

  condition:
    any of them
}