rule TTP_XOR_QUAD_CurrentVersionRun_d109 {
  strings:
    $key_d109 = { 82 66 [2] a6 68 [2] 8d 44 [2] a3 66 [2] b7 7d [2] b8 67 [2] a6 7a [2] a4 7b [2] bf 7d [2] a3 7a [2] bf 55 }

  condition:
    any of them
}