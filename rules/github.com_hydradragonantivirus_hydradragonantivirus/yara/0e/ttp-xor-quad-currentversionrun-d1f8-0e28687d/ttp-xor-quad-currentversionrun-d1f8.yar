rule TTP_XOR_QUAD_CurrentVersionRun_d1f8 {
  strings:
    $key_d1f8 = { 82 97 [2] a6 99 [2] 8d b5 [2] a3 97 [2] b7 8c [2] b8 96 [2] a6 8b [2] a4 8a [2] bf 8c [2] a3 8b [2] bf a4 }

  condition:
    any of them
}