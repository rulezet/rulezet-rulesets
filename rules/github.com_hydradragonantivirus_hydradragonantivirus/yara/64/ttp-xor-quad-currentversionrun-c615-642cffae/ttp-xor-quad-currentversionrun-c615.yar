rule TTP_XOR_QUAD_CurrentVersionRun_c615 {
  strings:
    $key_c615 = { 95 7a [2] b1 74 [2] 9a 58 [2] b4 7a [2] a0 61 [2] af 7b [2] b1 66 [2] b3 67 [2] a8 61 [2] b4 66 [2] a8 49 }

  condition:
    any of them
}