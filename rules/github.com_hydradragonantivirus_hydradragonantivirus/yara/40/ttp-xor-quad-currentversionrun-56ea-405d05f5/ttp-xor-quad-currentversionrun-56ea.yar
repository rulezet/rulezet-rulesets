rule TTP_XOR_QUAD_CurrentVersionRun_56ea {
  strings:
    $key_56ea = { 05 85 [2] 21 8b [2] 0a a7 [2] 24 85 [2] 30 9e [2] 3f 84 [2] 21 99 [2] 23 98 [2] 38 9e [2] 24 99 [2] 38 b6 }

  condition:
    any of them
}