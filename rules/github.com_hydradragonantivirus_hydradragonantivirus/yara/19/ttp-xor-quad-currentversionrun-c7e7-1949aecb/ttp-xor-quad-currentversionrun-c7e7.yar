rule TTP_XOR_QUAD_CurrentVersionRun_c7e7 {
  strings:
    $key_c7e7 = { 94 88 [2] b0 86 [2] 9b aa [2] b5 88 [2] a1 93 [2] ae 89 [2] b0 94 [2] b2 95 [2] a9 93 [2] b5 94 [2] a9 bb }

  condition:
    any of them
}