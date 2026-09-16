rule TTP_XOR_QUAD_CurrentVersionRun_15ea {
  strings:
    $key_15ea = { 46 85 [2] 62 8b [2] 49 a7 [2] 67 85 [2] 73 9e [2] 7c 84 [2] 62 99 [2] 60 98 [2] 7b 9e [2] 67 99 [2] 7b b6 }

  condition:
    any of them
}