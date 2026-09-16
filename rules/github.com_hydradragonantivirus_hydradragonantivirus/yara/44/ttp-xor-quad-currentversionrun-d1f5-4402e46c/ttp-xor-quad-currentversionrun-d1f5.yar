rule TTP_XOR_QUAD_CurrentVersionRun_d1f5 {
  strings:
    $key_d1f5 = { 82 9a [2] a6 94 [2] 8d b8 [2] a3 9a [2] b7 81 [2] b8 9b [2] a6 86 [2] a4 87 [2] bf 81 [2] a3 86 [2] bf a9 }

  condition:
    any of them
}