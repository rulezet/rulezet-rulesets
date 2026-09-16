rule TTP_XOR_QUAD_CurrentVersionRun_c1e7 {
  strings:
    $key_c1e7 = { 92 88 [2] b6 86 [2] 9d aa [2] b3 88 [2] a7 93 [2] a8 89 [2] b6 94 [2] b4 95 [2] af 93 [2] b3 94 [2] af bb }

  condition:
    any of them
}