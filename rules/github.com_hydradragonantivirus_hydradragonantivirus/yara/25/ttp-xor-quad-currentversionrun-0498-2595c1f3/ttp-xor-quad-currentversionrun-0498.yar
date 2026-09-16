rule TTP_XOR_QUAD_CurrentVersionRun_0498 {
  strings:
    $key_0498 = { 57 f7 [2] 73 f9 [2] 58 d5 [2] 76 f7 [2] 62 ec [2] 6d f6 [2] 73 eb [2] 71 ea [2] 6a ec [2] 76 eb [2] 6a c4 }

  condition:
    any of them
}