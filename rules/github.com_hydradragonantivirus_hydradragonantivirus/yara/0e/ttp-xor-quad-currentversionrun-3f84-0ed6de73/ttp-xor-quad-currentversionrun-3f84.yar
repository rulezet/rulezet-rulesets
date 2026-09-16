rule TTP_XOR_QUAD_CurrentVersionRun_3f84 {
  strings:
    $key_3f84 = { 6c eb [2] 48 e5 [2] 63 c9 [2] 4d eb [2] 59 f0 [2] 56 ea [2] 48 f7 [2] 4a f6 [2] 51 f0 [2] 4d f7 [2] 51 d8 }

  condition:
    any of them
}