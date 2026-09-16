rule TTP_XOR_QUAD_CurrentVersionRun_c184 {
  strings:
    $key_c184 = { 92 eb [2] b6 e5 [2] 9d c9 [2] b3 eb [2] a7 f0 [2] a8 ea [2] b6 f7 [2] b4 f6 [2] af f0 [2] b3 f7 [2] af d8 }

  condition:
    any of them
}