rule TTP_XOR_QUAD_CurrentVersionRun_c755 {
  strings:
    $key_c755 = { 94 3a [2] b0 34 [2] 9b 18 [2] b5 3a [2] a1 21 [2] ae 3b [2] b0 26 [2] b2 27 [2] a9 21 [2] b5 26 [2] a9 09 }

  condition:
    any of them
}