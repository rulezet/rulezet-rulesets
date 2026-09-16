rule TTP_XOR_QUAD_CurrentVersionRun_d099 {
  strings:
    $key_d099 = { 83 f6 [2] a7 f8 [2] 8c d4 [2] a2 f6 [2] b6 ed [2] b9 f7 [2] a7 ea [2] a5 eb [2] be ed [2] a2 ea [2] be c5 }

  condition:
    any of them
}