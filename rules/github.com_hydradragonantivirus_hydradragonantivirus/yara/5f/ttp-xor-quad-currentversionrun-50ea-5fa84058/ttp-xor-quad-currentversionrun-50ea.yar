rule TTP_XOR_QUAD_CurrentVersionRun_50ea {
  strings:
    $key_50ea = { 03 85 [2] 27 8b [2] 0c a7 [2] 22 85 [2] 36 9e [2] 39 84 [2] 27 99 [2] 25 98 [2] 3e 9e [2] 22 99 [2] 3e b6 }

  condition:
    any of them
}