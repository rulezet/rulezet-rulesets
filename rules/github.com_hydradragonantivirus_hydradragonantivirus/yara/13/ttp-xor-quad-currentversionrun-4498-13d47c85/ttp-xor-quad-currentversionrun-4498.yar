rule TTP_XOR_QUAD_CurrentVersionRun_4498 {
  strings:
    $key_4498 = { 17 f7 [2] 33 f9 [2] 18 d5 [2] 36 f7 [2] 22 ec [2] 2d f6 [2] 33 eb [2] 31 ea [2] 2a ec [2] 36 eb [2] 2a c4 }

  condition:
    any of them
}