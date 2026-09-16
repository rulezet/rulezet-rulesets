rule TTP_XOR_QUAD_CurrentVersionRun_e199 {
  strings:
    $key_e199 = { b2 f6 [2] 96 f8 [2] bd d4 [2] 93 f6 [2] 87 ed [2] 88 f7 [2] 96 ea [2] 94 eb [2] 8f ed [2] 93 ea [2] 8f c5 }

  condition:
    any of them
}