rule TTP_XOR_QUAD_CurrentVersionRun_c769 {
  strings:
    $key_c769 = { 94 06 [2] b0 08 [2] 9b 24 [2] b5 06 [2] a1 1d [2] ae 07 [2] b0 1a [2] b2 1b [2] a9 1d [2] b5 1a [2] a9 35 }

  condition:
    any of them
}