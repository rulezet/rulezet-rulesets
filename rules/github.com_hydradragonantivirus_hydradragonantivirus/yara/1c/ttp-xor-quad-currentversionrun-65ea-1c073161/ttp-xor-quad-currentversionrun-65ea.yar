rule TTP_XOR_QUAD_CurrentVersionRun_65ea {
  strings:
    $key_65ea = { 36 85 [2] 12 8b [2] 39 a7 [2] 17 85 [2] 03 9e [2] 0c 84 [2] 12 99 [2] 10 98 [2] 0b 9e [2] 17 99 [2] 0b b6 }

  condition:
    any of them
}