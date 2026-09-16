rule TTP_XOR_QUAD_CurrentVersionRun_c677 {
  strings:
    $key_c677 = { 95 18 [2] b1 16 [2] 9a 3a [2] b4 18 [2] a0 03 [2] af 19 [2] b1 04 [2] b3 05 [2] a8 03 [2] b4 04 [2] a8 2b }

  condition:
    any of them
}