rule TTP_XOR_QUAD_CurrentVersionRun_d6fb {
  strings:
    $key_d6fb = { 85 94 [2] a1 9a [2] 8a b6 [2] a4 94 [2] b0 8f [2] bf 95 [2] a1 88 [2] a3 89 [2] b8 8f [2] a4 88 [2] b8 a7 }

  condition:
    any of them
}