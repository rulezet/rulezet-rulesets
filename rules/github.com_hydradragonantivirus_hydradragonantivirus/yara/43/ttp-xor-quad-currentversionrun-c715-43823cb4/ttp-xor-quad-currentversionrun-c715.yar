rule TTP_XOR_QUAD_CurrentVersionRun_c715 {
  strings:
    $key_c715 = { 94 7a [2] b0 74 [2] 9b 58 [2] b5 7a [2] a1 61 [2] ae 7b [2] b0 66 [2] b2 67 [2] a9 61 [2] b5 66 [2] a9 49 }

  condition:
    any of them
}