rule TTP_XOR_QUAD_CurrentVersionRun_c654 {
  strings:
    $key_c654 = { 95 3b [2] b1 35 [2] 9a 19 [2] b4 3b [2] a0 20 [2] af 3a [2] b1 27 [2] b3 26 [2] a8 20 [2] b4 27 [2] a8 08 }

  condition:
    any of them
}