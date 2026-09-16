rule TTP_XOR_QUAD_CurrentVersionRun_d799 {
  strings:
    $key_d799 = { 84 f6 [2] a0 f8 [2] 8b d4 [2] a5 f6 [2] b1 ed [2] be f7 [2] a0 ea [2] a2 eb [2] b9 ed [2] a5 ea [2] b9 c5 }

  condition:
    any of them
}