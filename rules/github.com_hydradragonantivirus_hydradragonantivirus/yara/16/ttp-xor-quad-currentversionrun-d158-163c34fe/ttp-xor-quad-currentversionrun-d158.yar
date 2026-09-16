rule TTP_XOR_QUAD_CurrentVersionRun_d158 {
  strings:
    $key_d158 = { 82 37 [2] a6 39 [2] 8d 15 [2] a3 37 [2] b7 2c [2] b8 36 [2] a6 2b [2] a4 2a [2] bf 2c [2] a3 2b [2] bf 04 }

  condition:
    any of them
}