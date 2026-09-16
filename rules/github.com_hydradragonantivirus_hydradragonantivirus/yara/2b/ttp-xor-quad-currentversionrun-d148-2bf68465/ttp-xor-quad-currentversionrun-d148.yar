rule TTP_XOR_QUAD_CurrentVersionRun_d148 {
  strings:
    $key_d148 = { 82 27 [2] a6 29 [2] 8d 05 [2] a3 27 [2] b7 3c [2] b8 26 [2] a6 3b [2] a4 3a [2] bf 3c [2] a3 3b [2] bf 14 }

  condition:
    any of them
}