rule TTP_XOR_QUAD_CurrentVersionRun_dff4 {
  strings:
    $key_dff4 = { 8c 9b [2] a8 95 [2] 83 b9 [2] ad 9b [2] b9 80 [2] b6 9a [2] a8 87 [2] aa 86 [2] b1 80 [2] ad 87 [2] b1 a8 }

  condition:
    any of them
}