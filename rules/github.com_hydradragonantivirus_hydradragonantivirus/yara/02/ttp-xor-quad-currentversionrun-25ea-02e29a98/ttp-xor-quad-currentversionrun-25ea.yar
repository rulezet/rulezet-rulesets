rule TTP_XOR_QUAD_CurrentVersionRun_25ea {
  strings:
    $key_25ea = { 76 85 [2] 52 8b [2] 79 a7 [2] 57 85 [2] 43 9e [2] 4c 84 [2] 52 99 [2] 50 98 [2] 4b 9e [2] 57 99 [2] 4b b6 }

  condition:
    any of them
}