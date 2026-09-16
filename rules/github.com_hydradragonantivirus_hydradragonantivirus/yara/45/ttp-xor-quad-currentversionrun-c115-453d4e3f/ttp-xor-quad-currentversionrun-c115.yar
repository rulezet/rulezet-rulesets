rule TTP_XOR_QUAD_CurrentVersionRun_c115 {
  strings:
    $key_c115 = { 92 7a [2] b6 74 [2] 9d 58 [2] b3 7a [2] a7 61 [2] a8 7b [2] b6 66 [2] b4 67 [2] af 61 [2] b3 66 [2] af 49 }

  condition:
    any of them
}