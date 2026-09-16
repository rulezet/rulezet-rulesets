rule TTP_XOR_QUAD_CurrentVersionRun_5199 {
  strings:
    $key_5199 = { 02 f6 [2] 26 f8 [2] 0d d4 [2] 23 f6 [2] 37 ed [2] 38 f7 [2] 26 ea [2] 24 eb [2] 3f ed [2] 23 ea [2] 3f c5 }

  condition:
    any of them
}