rule TTP_XOR_QUAD_CurrentVersionRun_c774 {
  strings:
    $key_c774 = { 94 1b [2] b0 15 [2] 9b 39 [2] b5 1b [2] a1 00 [2] ae 1a [2] b0 07 [2] b2 06 [2] a9 00 [2] b5 07 [2] a9 28 }

  condition:
    any of them
}