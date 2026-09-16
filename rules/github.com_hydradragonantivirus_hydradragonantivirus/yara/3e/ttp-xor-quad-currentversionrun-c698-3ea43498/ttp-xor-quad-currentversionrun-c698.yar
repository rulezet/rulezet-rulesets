rule TTP_XOR_QUAD_CurrentVersionRun_c698 {
  strings:
    $key_c698 = { 95 f7 [2] b1 f9 [2] 9a d5 [2] b4 f7 [2] a0 ec [2] af f6 [2] b1 eb [2] b3 ea [2] a8 ec [2] b4 eb [2] a8 c4 }

  condition:
    any of them
}