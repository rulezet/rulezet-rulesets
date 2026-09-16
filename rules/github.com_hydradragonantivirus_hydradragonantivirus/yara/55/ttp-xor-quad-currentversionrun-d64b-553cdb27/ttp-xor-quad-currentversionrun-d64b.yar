rule TTP_XOR_QUAD_CurrentVersionRun_d64b {
  strings:
    $key_d64b = { 85 24 [2] a1 2a [2] 8a 06 [2] a4 24 [2] b0 3f [2] bf 25 [2] a1 38 [2] a3 39 [2] b8 3f [2] a4 38 [2] b8 17 }

  condition:
    any of them
}