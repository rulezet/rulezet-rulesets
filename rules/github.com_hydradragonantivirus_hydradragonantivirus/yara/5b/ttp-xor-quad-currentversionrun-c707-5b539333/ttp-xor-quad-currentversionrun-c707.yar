rule TTP_XOR_QUAD_CurrentVersionRun_c707 {
  strings:
    $key_c707 = { 94 68 [2] b0 66 [2] 9b 4a [2] b5 68 [2] a1 73 [2] ae 69 [2] b0 74 [2] b2 75 [2] a9 73 [2] b5 74 [2] a9 5b }

  condition:
    any of them
}