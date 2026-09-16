rule TTP_XOR_QUAD_CurrentVersionRun_de85 {
  strings:
    $key_de85 = { 8d ea [2] a9 e4 [2] 82 c8 [2] ac ea [2] b8 f1 [2] b7 eb [2] a9 f6 [2] ab f7 [2] b0 f1 [2] ac f6 [2] b0 d9 }

  condition:
    any of them
}