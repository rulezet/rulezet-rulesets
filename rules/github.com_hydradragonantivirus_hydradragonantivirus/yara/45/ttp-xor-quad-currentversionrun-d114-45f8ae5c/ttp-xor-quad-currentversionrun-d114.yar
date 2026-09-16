rule TTP_XOR_QUAD_CurrentVersionRun_d114 {
  strings:
    $key_d114 = { 82 7b [2] a6 75 [2] 8d 59 [2] a3 7b [2] b7 60 [2] b8 7a [2] a6 67 [2] a4 66 [2] bf 60 [2] a3 67 [2] bf 48 }

  condition:
    any of them
}