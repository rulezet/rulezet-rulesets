rule TTP_XOR_QUAD_CurrentVersionRun_c4e7 {
  strings:
    $key_c4e7 = { 97 88 [2] b3 86 [2] 98 aa [2] b6 88 [2] a2 93 [2] ad 89 [2] b3 94 [2] b1 95 [2] aa 93 [2] b6 94 [2] aa bb }

  condition:
    any of them
}