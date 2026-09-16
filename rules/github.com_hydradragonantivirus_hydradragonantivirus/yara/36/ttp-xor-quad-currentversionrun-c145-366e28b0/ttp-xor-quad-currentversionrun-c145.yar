rule TTP_XOR_QUAD_CurrentVersionRun_c145 {
  strings:
    $key_c145 = { 92 2a [2] b6 24 [2] 9d 08 [2] b3 2a [2] a7 31 [2] a8 2b [2] b6 36 [2] b4 37 [2] af 31 [2] b3 36 [2] af 19 }

  condition:
    any of them
}