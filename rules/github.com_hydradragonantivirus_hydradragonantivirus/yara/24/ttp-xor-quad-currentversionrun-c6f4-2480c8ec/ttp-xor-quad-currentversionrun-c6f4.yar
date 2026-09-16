rule TTP_XOR_QUAD_CurrentVersionRun_c6f4 {
  strings:
    $key_c6f4 = { 95 9b [2] b1 95 [2] 9a b9 [2] b4 9b [2] a0 80 [2] af 9a [2] b1 87 [2] b3 86 [2] a8 80 [2] b4 87 [2] a8 a8 }

  condition:
    any of them
}