rule TTP_XOR_QUAD_CurrentVersionRun_e7ea {
  strings:
    $key_e7ea = { b4 85 [2] 90 8b [2] bb a7 [2] 95 85 [2] 81 9e [2] 8e 84 [2] 90 99 [2] 92 98 [2] 89 9e [2] 95 99 [2] 89 b6 }

  condition:
    any of them
}