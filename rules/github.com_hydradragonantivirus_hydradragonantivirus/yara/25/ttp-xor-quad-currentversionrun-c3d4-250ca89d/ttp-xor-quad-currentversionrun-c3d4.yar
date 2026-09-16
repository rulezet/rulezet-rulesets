rule TTP_XOR_QUAD_CurrentVersionRun_c3d4 {
  strings:
    $key_c3d4 = { 90 bb [2] b4 b5 [2] 9f 99 [2] b1 bb [2] a5 a0 [2] aa ba [2] b4 a7 [2] b6 a6 [2] ad a0 [2] b1 a7 [2] ad 88 }

  condition:
    any of them
}