rule TTP_XOR_QUAD_CurrentVersionRun_07ea {
  strings:
    $key_07ea = { 54 85 [2] 70 8b [2] 5b a7 [2] 75 85 [2] 61 9e [2] 6e 84 [2] 70 99 [2] 72 98 [2] 69 9e [2] 75 99 [2] 69 b6 }

  condition:
    any of them
}