rule TTP_XOR_QUAD_CurrentVersionRun_d615 {
  strings:
    $key_d615 = { 85 7a [2] a1 74 [2] 8a 58 [2] a4 7a [2] b0 61 [2] bf 7b [2] a1 66 [2] a3 67 [2] b8 61 [2] a4 66 [2] b8 49 }

  condition:
    any of them
}