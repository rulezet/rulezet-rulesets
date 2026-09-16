rule TTP_XOR_QUAD_CurrentVersionRun_c2d4 {
  strings:
    $key_c2d4 = { 91 bb [2] b5 b5 [2] 9e 99 [2] b0 bb [2] a4 a0 [2] ab ba [2] b5 a7 [2] b7 a6 [2] ac a0 [2] b0 a7 [2] ac 88 }

  condition:
    any of them
}