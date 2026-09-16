rule TTP_XOR_QUAD_CurrentVersionRun_d6e9 {
  strings:
    $key_d6e9 = { 85 86 [2] a1 88 [2] 8a a4 [2] a4 86 [2] b0 9d [2] bf 87 [2] a1 9a [2] a3 9b [2] b8 9d [2] a4 9a [2] b8 b5 }

  condition:
    any of them
}