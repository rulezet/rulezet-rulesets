rule TTP_XOR_QUAD_CurrentVersionRun_c7fb {
  strings:
    $key_c7fb = { 94 94 [2] b0 9a [2] 9b b6 [2] b5 94 [2] a1 8f [2] ae 95 [2] b0 88 [2] b2 89 [2] a9 8f [2] b5 88 [2] a9 a7 }

  condition:
    any of them
}