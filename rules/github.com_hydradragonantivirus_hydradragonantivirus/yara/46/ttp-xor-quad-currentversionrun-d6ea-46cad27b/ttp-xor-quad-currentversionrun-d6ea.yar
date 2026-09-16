rule TTP_XOR_QUAD_CurrentVersionRun_d6ea {
  strings:
    $key_d6ea = { 85 85 [2] a1 8b [2] 8a a7 [2] a4 85 [2] b0 9e [2] bf 84 [2] a1 99 [2] a3 98 [2] b8 9e [2] a4 99 [2] b8 b6 }

  condition:
    any of them
}