rule TTP_XOR_QUAD_CurrentVersionRun_0f84 {
  strings:
    $key_0f84 = { 5c eb [2] 78 e5 [2] 53 c9 [2] 7d eb [2] 69 f0 [2] 66 ea [2] 78 f7 [2] 7a f6 [2] 61 f0 [2] 7d f7 [2] 61 d8 }

  condition:
    any of them
}