rule TTP_XOR_QUAD_CurrentVersionRun_c099 {
  strings:
    $key_c099 = { 93 f6 [2] b7 f8 [2] 9c d4 [2] b2 f6 [2] a6 ed [2] a9 f7 [2] b7 ea [2] b5 eb [2] ae ed [2] b2 ea [2] ae c5 }

  condition:
    any of them
}