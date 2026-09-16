rule TTP_XOR_QUAD_CurrentVersionRun_c6eb {
  strings:
    $key_c6eb = { 95 84 [2] b1 8a [2] 9a a6 [2] b4 84 [2] a0 9f [2] af 85 [2] b1 98 [2] b3 99 [2] a8 9f [2] b4 98 [2] a8 b7 }

  condition:
    any of them
}