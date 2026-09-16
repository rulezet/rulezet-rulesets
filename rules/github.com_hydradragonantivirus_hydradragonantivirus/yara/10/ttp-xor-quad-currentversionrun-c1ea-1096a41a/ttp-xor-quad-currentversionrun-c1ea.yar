rule TTP_XOR_QUAD_CurrentVersionRun_c1ea {
  strings:
    $key_c1ea = { 92 85 [2] b6 8b [2] 9d a7 [2] b3 85 [2] a7 9e [2] a8 84 [2] b6 99 [2] b4 98 [2] af 9e [2] b3 99 [2] af b6 }

  condition:
    any of them
}