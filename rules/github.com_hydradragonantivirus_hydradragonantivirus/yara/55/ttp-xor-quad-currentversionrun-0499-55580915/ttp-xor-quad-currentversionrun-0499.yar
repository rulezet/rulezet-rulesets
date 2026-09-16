rule TTP_XOR_QUAD_CurrentVersionRun_0499 {
  strings:
    $key_0499 = { 57 f6 [2] 73 f8 [2] 58 d4 [2] 76 f6 [2] 62 ed [2] 6d f7 [2] 73 ea [2] 71 eb [2] 6a ed [2] 76 ea [2] 6a c5 }

  condition:
    any of them
}