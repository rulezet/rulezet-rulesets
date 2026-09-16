rule TTP_XOR_QUAD_CurrentVersionRun_d7ea {
  strings:
    $key_d7ea = { 84 85 [2] a0 8b [2] 8b a7 [2] a5 85 [2] b1 9e [2] be 84 [2] a0 99 [2] a2 98 [2] b9 9e [2] a5 99 [2] b9 b6 }

  condition:
    any of them
}