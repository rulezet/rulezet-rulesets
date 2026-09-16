rule TTP_XOR_QUAD_CurrentVersionRun_c399 {
  strings:
    $key_c399 = { 90 f6 [2] b4 f8 [2] 9f d4 [2] b1 f6 [2] a5 ed [2] aa f7 [2] b4 ea [2] b6 eb [2] ad ed [2] b1 ea [2] ad c5 }

  condition:
    any of them
}