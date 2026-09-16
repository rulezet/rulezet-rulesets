rule TTP_XOR_QUAD_CurrentVersionRun_c475 {
  strings:
    $key_c475 = { 97 1a [2] b3 14 [2] 98 38 [2] b6 1a [2] a2 01 [2] ad 1b [2] b3 06 [2] b1 07 [2] aa 01 [2] b6 06 [2] aa 29 }

  condition:
    any of them
}