rule TTP_XOR_QUAD_CurrentVersionRun_c185 {
  strings:
    $key_c185 = { 92 ea [2] b6 e4 [2] 9d c8 [2] b3 ea [2] a7 f1 [2] a8 eb [2] b6 f6 [2] b4 f7 [2] af f1 [2] b3 f6 [2] af d9 }

  condition:
    any of them
}