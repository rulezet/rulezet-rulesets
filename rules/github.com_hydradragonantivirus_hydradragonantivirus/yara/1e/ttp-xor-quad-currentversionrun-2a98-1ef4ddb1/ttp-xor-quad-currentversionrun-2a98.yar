rule TTP_XOR_QUAD_CurrentVersionRun_2a98 {
  strings:
    $key_2a98 = { 79 f7 [2] 5d f9 [2] 76 d5 [2] 58 f7 [2] 4c ec [2] 43 f6 [2] 5d eb [2] 5f ea [2] 44 ec [2] 58 eb [2] 44 c4 }

  condition:
    any of them
}