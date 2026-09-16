rule TTP_XOR_QUAD_CurrentVersionRun_2199 {
  strings:
    $key_2199 = { 72 f6 [2] 56 f8 [2] 7d d4 [2] 53 f6 [2] 47 ed [2] 48 f7 [2] 56 ea [2] 54 eb [2] 4f ed [2] 53 ea [2] 4f c5 }

  condition:
    any of them
}