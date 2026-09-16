rule TTP_XOR_QUAD_CurrentVersionRun_c074 {
  strings:
    $key_c074 = { 93 1b [2] b7 15 [2] 9c 39 [2] b2 1b [2] a6 00 [2] a9 1a [2] b7 07 [2] b5 06 [2] ae 00 [2] b2 07 [2] ae 28 }

  condition:
    any of them
}