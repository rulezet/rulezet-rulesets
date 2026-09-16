rule TTP_XOR_QUAD_CurrentVersionRun_c6ea {
  strings:
    $key_c6ea = { 95 85 [2] b1 8b [2] 9a a7 [2] b4 85 [2] a0 9e [2] af 84 [2] b1 99 [2] b3 98 [2] a8 9e [2] b4 99 [2] a8 b6 }

  condition:
    any of them
}