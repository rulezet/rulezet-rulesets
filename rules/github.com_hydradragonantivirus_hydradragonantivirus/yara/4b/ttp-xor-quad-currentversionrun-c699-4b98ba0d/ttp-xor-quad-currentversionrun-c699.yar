rule TTP_XOR_QUAD_CurrentVersionRun_c699 {
  strings:
    $key_c699 = { 95 f6 [2] b1 f8 [2] 9a d4 [2] b4 f6 [2] a0 ed [2] af f7 [2] b1 ea [2] b3 eb [2] a8 ed [2] b4 ea [2] a8 c5 }

  condition:
    any of them
}