rule TTP_XOR_QUAD_CurrentVersionRun_d119 {
  strings:
    $key_d119 = { 82 76 [2] a6 78 [2] 8d 54 [2] a3 76 [2] b7 6d [2] b8 77 [2] a6 6a [2] a4 6b [2] bf 6d [2] a3 6a [2] bf 45 }

  condition:
    any of them
}