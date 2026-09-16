rule TTP_XOR_QUAD_CurrentVersionRun_c5c7 {
  strings:
    $key_c5c7 = { 96 a8 [2] b2 a6 [2] 99 8a [2] b7 a8 [2] a3 b3 [2] ac a9 [2] b2 b4 [2] b0 b5 [2] ab b3 [2] b7 b4 [2] ab 9b }

  condition:
    any of them
}