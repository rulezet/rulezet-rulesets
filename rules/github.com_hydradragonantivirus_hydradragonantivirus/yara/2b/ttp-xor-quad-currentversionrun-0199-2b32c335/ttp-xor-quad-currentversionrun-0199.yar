rule TTP_XOR_QUAD_CurrentVersionRun_0199 {
  strings:
    $key_0199 = { 52 f6 [2] 76 f8 [2] 5d d4 [2] 73 f6 [2] 67 ed [2] 68 f7 [2] 76 ea [2] 74 eb [2] 6f ed [2] 73 ea [2] 6f c5 }

  condition:
    any of them
}