rule TTP_XOR_QUAD_CurrentVersionRun_c175 {
  strings:
    $key_c175 = { 92 1a [2] b6 14 [2] 9d 38 [2] b3 1a [2] a7 01 [2] a8 1b [2] b6 06 [2] b4 07 [2] af 01 [2] b3 06 [2] af 29 }

  condition:
    any of them
}