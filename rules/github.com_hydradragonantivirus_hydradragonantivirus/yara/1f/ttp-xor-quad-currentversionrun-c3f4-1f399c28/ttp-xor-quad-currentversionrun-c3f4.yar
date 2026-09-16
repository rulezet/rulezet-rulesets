rule TTP_XOR_QUAD_CurrentVersionRun_c3f4 {
  strings:
    $key_c3f4 = { 90 9b [2] b4 95 [2] 9f b9 [2] b1 9b [2] a5 80 [2] aa 9a [2] b4 87 [2] b6 86 [2] ad 80 [2] b1 87 [2] ad a8 }

  condition:
    any of them
}