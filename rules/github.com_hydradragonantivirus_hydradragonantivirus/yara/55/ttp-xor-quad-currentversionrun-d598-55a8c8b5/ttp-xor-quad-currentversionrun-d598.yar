rule TTP_XOR_QUAD_CurrentVersionRun_d598 {
  strings:
    $key_d598 = { 86 f7 [2] a2 f9 [2] 89 d5 [2] a7 f7 [2] b3 ec [2] bc f6 [2] a2 eb [2] a0 ea [2] bb ec [2] a7 eb [2] bb c4 }

  condition:
    any of them
}