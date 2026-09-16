rule TTP_XOR_QUAD_CurrentVersionRun_d1e8 {
  strings:
    $key_d1e8 = { 82 87 [2] a6 89 [2] 8d a5 [2] a3 87 [2] b7 9c [2] b8 86 [2] a6 9b [2] a4 9a [2] bf 9c [2] a3 9b [2] bf b4 }

  condition:
    any of them
}