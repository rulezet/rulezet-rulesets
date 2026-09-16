rule TTP_XOR_QUAD_CurrentVersionRun_f4ea {
  strings:
    $key_f4ea = { a7 85 [2] 83 8b [2] a8 a7 [2] 86 85 [2] 92 9e [2] 9d 84 [2] 83 99 [2] 81 98 [2] 9a 9e [2] 86 99 [2] 9a b6 }

  condition:
    any of them
}