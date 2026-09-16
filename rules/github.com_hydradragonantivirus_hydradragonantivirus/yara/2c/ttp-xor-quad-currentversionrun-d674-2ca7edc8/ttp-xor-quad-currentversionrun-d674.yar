rule TTP_XOR_QUAD_CurrentVersionRun_d674 {
  strings:
    $key_d674 = { 85 1b [2] a1 15 [2] 8a 39 [2] a4 1b [2] b0 00 [2] bf 1a [2] a1 07 [2] a3 06 [2] b8 00 [2] a4 07 [2] b8 28 }

  condition:
    any of them
}