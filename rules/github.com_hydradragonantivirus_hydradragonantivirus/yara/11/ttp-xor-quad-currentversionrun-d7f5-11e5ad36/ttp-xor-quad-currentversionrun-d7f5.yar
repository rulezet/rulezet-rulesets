rule TTP_XOR_QUAD_CurrentVersionRun_d7f5 {
  strings:
    $key_d7f5 = { 84 9a [2] a0 94 [2] 8b b8 [2] a5 9a [2] b1 81 [2] be 9b [2] a0 86 [2] a2 87 [2] b9 81 [2] a5 86 [2] b9 a9 }

  condition:
    any of them
}