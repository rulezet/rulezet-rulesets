rule TTP_XOR_QUAD_CurrentVersionRun_28ea {
  strings:
    $key_28ea = { 7b 85 [2] 5f 8b [2] 74 a7 [2] 5a 85 [2] 4e 9e [2] 41 84 [2] 5f 99 [2] 5d 98 [2] 46 9e [2] 5a 99 [2] 46 b6 }

  condition:
    any of them
}