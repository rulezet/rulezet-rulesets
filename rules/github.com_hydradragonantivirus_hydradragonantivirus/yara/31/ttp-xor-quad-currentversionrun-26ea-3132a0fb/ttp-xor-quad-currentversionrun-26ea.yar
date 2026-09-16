rule TTP_XOR_QUAD_CurrentVersionRun_26ea {
  strings:
    $key_26ea = { 75 85 [2] 51 8b [2] 7a a7 [2] 54 85 [2] 40 9e [2] 4f 84 [2] 51 99 [2] 53 98 [2] 48 9e [2] 54 99 [2] 48 b6 }

  condition:
    any of them
}