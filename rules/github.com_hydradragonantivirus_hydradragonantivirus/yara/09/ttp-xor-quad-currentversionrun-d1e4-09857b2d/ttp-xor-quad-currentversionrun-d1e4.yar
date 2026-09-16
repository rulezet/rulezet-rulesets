rule TTP_XOR_QUAD_CurrentVersionRun_d1e4 {
  strings:
    $key_d1e4 = { 82 8b [2] a6 85 [2] 8d a9 [2] a3 8b [2] b7 90 [2] b8 8a [2] a6 97 [2] a4 96 [2] bf 90 [2] a3 97 [2] bf b8 }

  condition:
    any of them
}