rule TTP_XOR_QUAD_CurrentVersionRun_d145 {
  strings:
    $key_d145 = { 82 2a [2] a6 24 [2] 8d 08 [2] a3 2a [2] b7 31 [2] b8 2b [2] a6 36 [2] a4 37 [2] bf 31 [2] a3 36 [2] bf 19 }

  condition:
    any of them
}