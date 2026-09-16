rule TTP_XOR_QUAD_CurrentVersionRun_16ea {
  strings:
    $key_16ea = { 45 85 [2] 61 8b [2] 4a a7 [2] 64 85 [2] 70 9e [2] 7f 84 [2] 61 99 [2] 63 98 [2] 78 9e [2] 64 99 [2] 78 b6 }

  condition:
    any of them
}