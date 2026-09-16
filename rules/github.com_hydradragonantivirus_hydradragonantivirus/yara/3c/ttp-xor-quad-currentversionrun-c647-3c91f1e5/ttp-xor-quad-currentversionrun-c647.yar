rule TTP_XOR_QUAD_CurrentVersionRun_c647 {
  strings:
    $key_c647 = { 95 28 [2] b1 26 [2] 9a 0a [2] b4 28 [2] a0 33 [2] af 29 [2] b1 34 [2] b3 35 [2] a8 33 [2] b4 34 [2] a8 1b }

  condition:
    any of them
}