rule TTP_XOR_QUAD_CurrentVersionRun_c784 {
  strings:
    $key_c784 = { 94 eb [2] b0 e5 [2] 9b c9 [2] b5 eb [2] a1 f0 [2] ae ea [2] b0 f7 [2] b2 f6 [2] a9 f0 [2] b5 f7 [2] a9 d8 }

  condition:
    any of them
}