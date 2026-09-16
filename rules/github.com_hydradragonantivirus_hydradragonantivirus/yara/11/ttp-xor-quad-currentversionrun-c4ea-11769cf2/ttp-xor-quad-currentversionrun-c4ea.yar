rule TTP_XOR_QUAD_CurrentVersionRun_c4ea {
  strings:
    $key_c4ea = { 97 85 [2] b3 8b [2] 98 a7 [2] b6 85 [2] a2 9e [2] ad 84 [2] b3 99 [2] b1 98 [2] aa 9e [2] b6 99 [2] aa b6 }

  condition:
    any of them
}