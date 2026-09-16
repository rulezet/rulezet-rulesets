rule TTP_XOR_QUAD_CurrentVersionRun_d6f4 {
  strings:
    $key_d6f4 = { 85 9b [2] a1 95 [2] 8a b9 [2] a4 9b [2] b0 80 [2] bf 9a [2] a1 87 [2] a3 86 [2] b8 80 [2] a4 87 [2] b8 a8 }

  condition:
    any of them
}