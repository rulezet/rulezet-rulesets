rule TTP_XOR_QUAD_CurrentVersionRun_c664 {
  strings:
    $key_c664 = { 95 0b [2] b1 05 [2] 9a 29 [2] b4 0b [2] a0 10 [2] af 0a [2] b1 17 [2] b3 16 [2] a8 10 [2] b4 17 [2] a8 38 }

  condition:
    any of them
}