rule TTP_XOR_QUAD_CurrentVersionRun_3498 {
  strings:
    $key_3498 = { 67 f7 [2] 43 f9 [2] 68 d5 [2] 46 f7 [2] 52 ec [2] 5d f6 [2] 43 eb [2] 41 ea [2] 5a ec [2] 46 eb [2] 5a c4 }

  condition:
    any of them
}