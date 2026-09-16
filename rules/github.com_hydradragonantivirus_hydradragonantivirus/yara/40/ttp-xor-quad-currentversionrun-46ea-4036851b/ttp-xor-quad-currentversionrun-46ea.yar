rule TTP_XOR_QUAD_CurrentVersionRun_46ea {
  strings:
    $key_46ea = { 15 85 [2] 31 8b [2] 1a a7 [2] 34 85 [2] 20 9e [2] 2f 84 [2] 31 99 [2] 33 98 [2] 28 9e [2] 34 99 [2] 28 b6 }

  condition:
    any of them
}