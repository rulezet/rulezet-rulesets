rule TTP_XOR_QUAD_CurrentVersionRun_17ea {
  strings:
    $key_17ea = { 44 85 [2] 60 8b [2] 4b a7 [2] 65 85 [2] 71 9e [2] 7e 84 [2] 60 99 [2] 62 98 [2] 79 9e [2] 65 99 [2] 79 b6 }

  condition:
    any of them
}