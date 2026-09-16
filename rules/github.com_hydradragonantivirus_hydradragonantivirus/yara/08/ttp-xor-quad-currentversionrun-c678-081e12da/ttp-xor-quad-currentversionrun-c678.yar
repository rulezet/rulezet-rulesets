rule TTP_XOR_QUAD_CurrentVersionRun_c678 {
  strings:
    $key_c678 = { 95 17 [2] b1 19 [2] 9a 35 [2] b4 17 [2] a0 0c [2] af 16 [2] b1 0b [2] b3 0a [2] a8 0c [2] b4 0b [2] a8 24 }

  condition:
    any of them
}