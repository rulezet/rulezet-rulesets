rule TTP_XOR_QUAD_CurrentVersionRun_7a98 {
  strings:
    $key_7a98 = { 29 f7 [2] 0d f9 [2] 26 d5 [2] 08 f7 [2] 1c ec [2] 13 f6 [2] 0d eb [2] 0f ea [2] 14 ec [2] 08 eb [2] 14 c4 }

  condition:
    any of them
}