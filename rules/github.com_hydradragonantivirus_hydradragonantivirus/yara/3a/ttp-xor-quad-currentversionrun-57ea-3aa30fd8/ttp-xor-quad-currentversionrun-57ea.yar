rule TTP_XOR_QUAD_CurrentVersionRun_57ea {
  strings:
    $key_57ea = { 04 85 [2] 20 8b [2] 0b a7 [2] 25 85 [2] 31 9e [2] 3e 84 [2] 20 99 [2] 22 98 [2] 39 9e [2] 25 99 [2] 39 b6 }

  condition:
    any of them
}