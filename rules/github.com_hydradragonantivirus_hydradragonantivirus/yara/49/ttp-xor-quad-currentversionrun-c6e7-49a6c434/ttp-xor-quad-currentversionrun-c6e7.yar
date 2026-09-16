rule TTP_XOR_QUAD_CurrentVersionRun_c6e7 {
  strings:
    $key_c6e7 = { 95 88 [2] b1 86 [2] 9a aa [2] b4 88 [2] a0 93 [2] af 89 [2] b1 94 [2] b3 95 [2] a8 93 [2] b4 94 [2] a8 bb }

  condition:
    any of them
}