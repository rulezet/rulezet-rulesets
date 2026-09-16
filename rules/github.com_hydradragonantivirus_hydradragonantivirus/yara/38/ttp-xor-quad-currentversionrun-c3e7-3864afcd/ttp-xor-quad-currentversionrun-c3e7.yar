rule TTP_XOR_QUAD_CurrentVersionRun_c3e7 {
  strings:
    $key_c3e7 = { 90 88 [2] b4 86 [2] 9f aa [2] b1 88 [2] a5 93 [2] aa 89 [2] b4 94 [2] b6 95 [2] ad 93 [2] b1 94 [2] ad bb }

  condition:
    any of them
}