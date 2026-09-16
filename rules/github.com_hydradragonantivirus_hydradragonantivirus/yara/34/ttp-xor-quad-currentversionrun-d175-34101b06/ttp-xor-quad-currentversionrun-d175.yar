rule TTP_XOR_QUAD_CurrentVersionRun_d175 {
  strings:
    $key_d175 = { 82 1a [2] a6 14 [2] 8d 38 [2] a3 1a [2] b7 01 [2] b8 1b [2] a6 06 [2] a4 07 [2] bf 01 [2] a3 06 [2] bf 29 }

  condition:
    any of them
}