rule TTP_XOR_QUAD_CurrentVersionRun_c0fb {
  strings:
    $key_c0fb = { 93 94 [2] b7 9a [2] 9c b6 [2] b2 94 [2] a6 8f [2] a9 95 [2] b7 88 [2] b5 89 [2] ae 8f [2] b2 88 [2] ae a7 }

  condition:
    any of them
}