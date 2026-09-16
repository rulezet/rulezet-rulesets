rule TTP_XOR_QUAD_CurrentVersionRun_10ea {
  strings:
    $key_10ea = { 43 85 [2] 67 8b [2] 4c a7 [2] 62 85 [2] 76 9e [2] 79 84 [2] 67 99 [2] 65 98 [2] 7e 9e [2] 62 99 [2] 7e b6 }

  condition:
    any of them
}