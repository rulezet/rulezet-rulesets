rule TTP_XOR_QUAD_CurrentVersionRun_c7f8 {
  strings:
    $key_c7f8 = { 94 97 [2] b0 99 [2] 9b b5 [2] b5 97 [2] a1 8c [2] ae 96 [2] b0 8b [2] b2 8a [2] a9 8c [2] b5 8b [2] a9 a4 }

  condition:
    any of them
}