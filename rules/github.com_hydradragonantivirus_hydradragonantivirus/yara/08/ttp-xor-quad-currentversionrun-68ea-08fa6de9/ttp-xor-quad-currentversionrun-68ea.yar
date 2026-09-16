rule TTP_XOR_QUAD_CurrentVersionRun_68ea {
  strings:
    $key_68ea = { 3b 85 [2] 1f 8b [2] 34 a7 [2] 1a 85 [2] 0e 9e [2] 01 84 [2] 1f 99 [2] 1d 98 [2] 06 9e [2] 1a 99 [2] 06 b6 }

  condition:
    any of them
}