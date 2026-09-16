rule TTP_XOR_QUAD_CurrentVersionRun_d199 {
  strings:
    $key_d199 = { 82 f6 [2] a6 f8 [2] 8d d4 [2] a3 f6 [2] b7 ed [2] b8 f7 [2] a6 ea [2] a4 eb [2] bf ed [2] a3 ea [2] bf c5 }

  condition:
    any of them
}