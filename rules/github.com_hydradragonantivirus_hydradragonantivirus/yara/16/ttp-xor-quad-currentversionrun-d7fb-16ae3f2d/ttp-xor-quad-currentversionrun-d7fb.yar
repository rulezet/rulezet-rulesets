rule TTP_XOR_QUAD_CurrentVersionRun_d7fb {
  strings:
    $key_d7fb = { 84 94 [2] a0 9a [2] 8b b6 [2] a5 94 [2] b1 8f [2] be 95 [2] a0 88 [2] a2 89 [2] b9 8f [2] a5 88 [2] b9 a7 }

  condition:
    any of them
}