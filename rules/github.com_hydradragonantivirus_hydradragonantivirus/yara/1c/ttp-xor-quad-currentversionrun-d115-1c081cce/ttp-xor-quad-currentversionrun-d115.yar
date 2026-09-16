rule TTP_XOR_QUAD_CurrentVersionRun_d115 {
  strings:
    $key_d115 = { 82 7a [2] a6 74 [2] 8d 58 [2] a3 7a [2] b7 61 [2] b8 7b [2] a6 66 [2] a4 67 [2] bf 61 [2] a3 66 [2] bf 49 }

  condition:
    any of them
}