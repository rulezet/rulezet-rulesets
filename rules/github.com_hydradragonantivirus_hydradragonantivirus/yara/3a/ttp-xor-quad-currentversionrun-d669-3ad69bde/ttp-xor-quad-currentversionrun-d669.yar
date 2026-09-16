rule TTP_XOR_QUAD_CurrentVersionRun_d669 {
  strings:
    $key_d669 = { 85 06 [2] a1 08 [2] 8a 24 [2] a4 06 [2] b0 1d [2] bf 07 [2] a1 1a [2] a3 1b [2] b8 1d [2] a4 1a [2] b8 35 }

  condition:
    any of them
}