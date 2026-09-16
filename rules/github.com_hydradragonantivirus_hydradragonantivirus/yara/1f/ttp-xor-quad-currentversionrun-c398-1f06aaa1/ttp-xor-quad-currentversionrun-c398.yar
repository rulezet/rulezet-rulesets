rule TTP_XOR_QUAD_CurrentVersionRun_c398 {
  strings:
    $key_c398 = { 90 f7 [2] b4 f9 [2] 9f d5 [2] b1 f7 [2] a5 ec [2] aa f6 [2] b4 eb [2] b6 ea [2] ad ec [2] b1 eb [2] ad c4 }

  condition:
    any of them
}