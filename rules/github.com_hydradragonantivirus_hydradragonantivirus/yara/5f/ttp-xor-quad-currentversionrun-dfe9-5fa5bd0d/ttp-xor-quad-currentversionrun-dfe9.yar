rule TTP_XOR_QUAD_CurrentVersionRun_dfe9 {
  strings:
    $key_dfe9 = { 8c 86 [2] a8 88 [2] 83 a4 [2] ad 86 [2] b9 9d [2] b6 87 [2] a8 9a [2] aa 9b [2] b1 9d [2] ad 9a [2] b1 b5 }

  condition:
    any of them
}