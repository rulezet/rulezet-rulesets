rule TTP_XOR_QUAD_CurrentVersionRun_d6eb {
  strings:
    $key_d6eb = { 85 84 [2] a1 8a [2] 8a a6 [2] a4 84 [2] b0 9f [2] bf 85 [2] a1 98 [2] a3 99 [2] b8 9f [2] a4 98 [2] b8 b7 }

  condition:
    any of them
}