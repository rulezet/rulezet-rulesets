rule TTP_XOR_QUAD_CurrentVersionRun_1498 {
  strings:
    $key_1498 = { 47 f7 [2] 63 f9 [2] 48 d5 [2] 66 f7 [2] 72 ec [2] 7d f6 [2] 63 eb [2] 61 ea [2] 7a ec [2] 66 eb [2] 7a c4 }

  condition:
    any of them
}