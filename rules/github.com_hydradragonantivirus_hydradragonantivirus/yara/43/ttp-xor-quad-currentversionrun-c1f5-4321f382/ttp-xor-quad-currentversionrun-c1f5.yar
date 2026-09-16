rule TTP_XOR_QUAD_CurrentVersionRun_c1f5 {
  strings:
    $key_c1f5 = { 92 9a [2] b6 94 [2] 9d b8 [2] b3 9a [2] a7 81 [2] a8 9b [2] b6 86 [2] b4 87 [2] af 81 [2] b3 86 [2] af a9 }

  condition:
    any of them
}