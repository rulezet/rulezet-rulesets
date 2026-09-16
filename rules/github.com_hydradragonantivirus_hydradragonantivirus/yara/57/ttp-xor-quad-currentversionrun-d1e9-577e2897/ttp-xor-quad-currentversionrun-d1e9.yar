rule TTP_XOR_QUAD_CurrentVersionRun_d1e9 {
  strings:
    $key_d1e9 = { 82 86 [2] a6 88 [2] 8d a4 [2] a3 86 [2] b7 9d [2] b8 87 [2] a6 9a [2] a4 9b [2] bf 9d [2] a3 9a [2] bf b5 }

  condition:
    any of them
}