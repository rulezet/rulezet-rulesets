rule TTP_XOR_QUAD_CurrentVersionRun_40ea {
  strings:
    $key_40ea = { 13 85 [2] 37 8b [2] 1c a7 [2] 32 85 [2] 26 9e [2] 29 84 [2] 37 99 [2] 35 98 [2] 2e 9e [2] 32 99 [2] 2e b6 }

  condition:
    any of them
}