rule TTP_XOR_QUAD_CurrentVersionRun_2f84 {
  strings:
    $key_2f84 = { 7c eb [2] 58 e5 [2] 73 c9 [2] 5d eb [2] 49 f0 [2] 46 ea [2] 58 f7 [2] 5a f6 [2] 41 f0 [2] 5d f7 [2] 41 d8 }

  condition:
    any of them
}