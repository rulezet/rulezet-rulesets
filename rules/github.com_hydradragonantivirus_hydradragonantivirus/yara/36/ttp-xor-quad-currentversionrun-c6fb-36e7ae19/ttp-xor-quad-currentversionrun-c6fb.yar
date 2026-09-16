rule TTP_XOR_QUAD_CurrentVersionRun_c6fb {
  strings:
    $key_c6fb = { 95 94 [2] b1 9a [2] 9a b6 [2] b4 94 [2] a0 8f [2] af 95 [2] b1 88 [2] b3 89 [2] a8 8f [2] b4 88 [2] a8 a7 }

  condition:
    any of them
}