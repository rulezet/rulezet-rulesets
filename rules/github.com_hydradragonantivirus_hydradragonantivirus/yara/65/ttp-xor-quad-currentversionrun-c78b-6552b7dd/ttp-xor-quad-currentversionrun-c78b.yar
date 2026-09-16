rule TTP_XOR_QUAD_CurrentVersionRun_c78b {
  strings:
    $key_c78b = { 94 e4 [2] b0 ea [2] 9b c6 [2] b5 e4 [2] a1 ff [2] ae e5 [2] b0 f8 [2] b2 f9 [2] a9 ff [2] b5 f8 [2] a9 d7 }

  condition:
    any of them
}