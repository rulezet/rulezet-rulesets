rule TTP_XOR_QUAD_CurrentVersionRun_6499 {
  strings:
    $key_6499 = { 37 f6 [2] 13 f8 [2] 38 d4 [2] 16 f6 [2] 02 ed [2] 0d f7 [2] 13 ea [2] 11 eb [2] 0a ed [2] 16 ea [2] 0a c5 }

  condition:
    any of them
}