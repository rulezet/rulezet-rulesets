rule TTP_XOR_QUAD_CurrentVersionRun_c775 {
  strings:
    $key_c775 = { 94 1a [2] b0 14 [2] 9b 38 [2] b5 1a [2] a1 01 [2] ae 1b [2] b0 06 [2] b2 07 [2] a9 01 [2] b5 06 [2] a9 29 }

  condition:
    any of them
}