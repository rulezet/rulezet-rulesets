rule TTP_XOR_QUAD_CurrentVersionRun_c4fb {
  strings:
    $key_c4fb = { 97 94 [2] b3 9a [2] 98 b6 [2] b6 94 [2] a2 8f [2] ad 95 [2] b3 88 [2] b1 89 [2] aa 8f [2] b6 88 [2] aa a7 }

  condition:
    any of them
}