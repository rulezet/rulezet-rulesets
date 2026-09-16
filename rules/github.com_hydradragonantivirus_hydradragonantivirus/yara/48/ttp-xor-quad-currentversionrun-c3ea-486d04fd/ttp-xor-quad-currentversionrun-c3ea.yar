rule TTP_XOR_QUAD_CurrentVersionRun_c3ea {
  strings:
    $key_c3ea = { 90 85 [2] b4 8b [2] 9f a7 [2] b1 85 [2] a5 9e [2] aa 84 [2] b4 99 [2] b6 98 [2] ad 9e [2] b1 99 [2] ad b6 }

  condition:
    any of them
}