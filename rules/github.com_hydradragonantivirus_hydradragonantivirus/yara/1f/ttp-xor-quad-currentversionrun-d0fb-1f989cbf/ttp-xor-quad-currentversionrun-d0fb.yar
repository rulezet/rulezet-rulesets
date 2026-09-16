rule TTP_XOR_QUAD_CurrentVersionRun_d0fb {
  strings:
    $key_d0fb = { 83 94 [2] a7 9a [2] 8c b6 [2] a2 94 [2] b6 8f [2] b9 95 [2] a7 88 [2] a5 89 [2] be 8f [2] a2 88 [2] be a7 }

  condition:
    any of them
}