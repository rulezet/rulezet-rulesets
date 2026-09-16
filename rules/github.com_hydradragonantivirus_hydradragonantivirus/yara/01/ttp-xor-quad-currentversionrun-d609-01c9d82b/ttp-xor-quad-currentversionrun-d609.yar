rule TTP_XOR_QUAD_CurrentVersionRun_d609 {
  strings:
    $key_d609 = { 85 66 [2] a1 68 [2] 8a 44 [2] a4 66 [2] b0 7d [2] bf 67 [2] a1 7a [2] a3 7b [2] b8 7d [2] a4 7a [2] b8 55 }

  condition:
    any of them
}