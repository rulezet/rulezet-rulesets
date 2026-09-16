rule TTP_XOR_QUAD_CurrentVersionRun_c7ea {
  strings:
    $key_c7ea = { 94 85 [2] b0 8b [2] 9b a7 [2] b5 85 [2] a1 9e [2] ae 84 [2] b0 99 [2] b2 98 [2] a9 9e [2] b5 99 [2] a9 b6 }

  condition:
    any of them
}