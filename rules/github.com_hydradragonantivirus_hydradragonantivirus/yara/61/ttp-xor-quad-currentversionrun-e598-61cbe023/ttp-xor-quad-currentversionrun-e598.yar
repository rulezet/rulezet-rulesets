rule TTP_XOR_QUAD_CurrentVersionRun_e598 {
  strings:
    $key_e598 = { b6 f7 [2] 92 f9 [2] b9 d5 [2] 97 f7 [2] 83 ec [2] 8c f6 [2] 92 eb [2] 90 ea [2] 8b ec [2] 97 eb [2] 8b c4 }

  condition:
    any of them
}