rule TTP_XOR_QUAD_CurrentVersionRun_64ea {
  strings:
    $key_64ea = { 37 85 [2] 13 8b [2] 38 a7 [2] 16 85 [2] 02 9e [2] 0d 84 [2] 13 99 [2] 11 98 [2] 0a 9e [2] 16 99 [2] 0a b6 }

  condition:
    any of them
}