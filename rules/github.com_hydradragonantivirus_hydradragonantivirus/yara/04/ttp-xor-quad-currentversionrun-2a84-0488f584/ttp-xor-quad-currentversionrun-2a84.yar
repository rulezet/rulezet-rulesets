rule TTP_XOR_QUAD_CurrentVersionRun_2a84 {
  strings:
    $key_2a84 = { 79 eb [2] 5d e5 [2] 76 c9 [2] 58 eb [2] 4c f0 [2] 43 ea [2] 5d f7 [2] 5f f6 [2] 44 f0 [2] 58 f7 [2] 44 d8 }

  condition:
    any of them
}