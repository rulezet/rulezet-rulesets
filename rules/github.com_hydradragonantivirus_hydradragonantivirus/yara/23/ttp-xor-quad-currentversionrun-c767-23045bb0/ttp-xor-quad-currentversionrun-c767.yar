rule TTP_XOR_QUAD_CurrentVersionRun_c767 {
  strings:
    $key_c767 = { 94 08 [2] b0 06 [2] 9b 2a [2] b5 08 [2] a1 13 [2] ae 09 [2] b0 14 [2] b2 15 [2] a9 13 [2] b5 14 [2] a9 3b }

  condition:
    any of them
}