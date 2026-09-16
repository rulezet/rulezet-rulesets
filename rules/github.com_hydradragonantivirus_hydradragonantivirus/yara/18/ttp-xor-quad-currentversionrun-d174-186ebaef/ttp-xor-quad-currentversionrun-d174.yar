rule TTP_XOR_QUAD_CurrentVersionRun_d174 {
  strings:
    $key_d174 = { 82 1b [2] a6 15 [2] 8d 39 [2] a3 1b [2] b7 00 [2] b8 1a [2] a6 07 [2] a4 06 [2] bf 00 [2] a3 07 [2] bf 28 }

  condition:
    any of them
}