rule TTP_XOR_QUAD_CurrentVersionRun_c4f4 {
  strings:
    $key_c4f4 = { 97 9b [2] b3 95 [2] 98 b9 [2] b6 9b [2] a2 80 [2] ad 9a [2] b3 87 [2] b1 86 [2] aa 80 [2] b6 87 [2] aa a8 }

  condition:
    any of them
}