rule TTP_XOR_QUAD_CurrentVersionRun_d168 {
  strings:
    $key_d168 = { 82 07 [2] a6 09 [2] 8d 25 [2] a3 07 [2] b7 1c [2] b8 06 [2] a6 1b [2] a4 1a [2] bf 1c [2] a3 1b [2] bf 34 }

  condition:
    any of them
}