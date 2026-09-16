rule TTP_XOR_QUAD_CurrentVersionRun_c179 {
  strings:
    $key_c179 = { 92 16 [2] b6 18 [2] 9d 34 [2] b3 16 [2] a7 0d [2] a8 17 [2] b6 0a [2] b4 0b [2] af 0d [2] b3 0a [2] af 25 }

  condition:
    any of them
}