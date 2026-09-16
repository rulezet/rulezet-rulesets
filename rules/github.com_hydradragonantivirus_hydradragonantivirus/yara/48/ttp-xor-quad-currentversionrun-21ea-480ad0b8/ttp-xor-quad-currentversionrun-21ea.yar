rule TTP_XOR_QUAD_CurrentVersionRun_21ea {
  strings:
    $key_21ea = { 72 85 [2] 56 8b [2] 7d a7 [2] 53 85 [2] 47 9e [2] 48 84 [2] 56 99 [2] 54 98 [2] 4f 9e [2] 53 99 [2] 4f b6 }

  condition:
    any of them
}