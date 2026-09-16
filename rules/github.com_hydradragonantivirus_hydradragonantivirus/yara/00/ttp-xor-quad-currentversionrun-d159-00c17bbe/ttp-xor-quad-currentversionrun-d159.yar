rule TTP_XOR_QUAD_CurrentVersionRun_d159 {
  strings:
    $key_d159 = { 82 36 [2] a6 38 [2] 8d 14 [2] a3 36 [2] b7 2d [2] b8 37 [2] a6 2a [2] a4 2b [2] bf 2d [2] a3 2a [2] bf 05 }

  condition:
    any of them
}