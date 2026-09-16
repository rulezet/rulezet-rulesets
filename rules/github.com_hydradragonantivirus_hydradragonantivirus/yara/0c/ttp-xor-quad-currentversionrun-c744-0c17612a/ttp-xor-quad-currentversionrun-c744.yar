rule TTP_XOR_QUAD_CurrentVersionRun_c744 {
  strings:
    $key_c744 = { 94 2b [2] b0 25 [2] 9b 09 [2] b5 2b [2] a1 30 [2] ae 2a [2] b0 37 [2] b2 36 [2] a9 30 [2] b5 37 [2] a9 18 }

  condition:
    any of them
}