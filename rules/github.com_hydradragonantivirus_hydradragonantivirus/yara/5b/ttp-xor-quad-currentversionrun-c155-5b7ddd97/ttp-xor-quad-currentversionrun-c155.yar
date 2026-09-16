rule TTP_XOR_QUAD_CurrentVersionRun_c155 {
  strings:
    $key_c155 = { 92 3a [2] b6 34 [2] 9d 18 [2] b3 3a [2] a7 21 [2] a8 3b [2] b6 26 [2] b4 27 [2] af 21 [2] b3 26 [2] af 09 }

  condition:
    any of them
}