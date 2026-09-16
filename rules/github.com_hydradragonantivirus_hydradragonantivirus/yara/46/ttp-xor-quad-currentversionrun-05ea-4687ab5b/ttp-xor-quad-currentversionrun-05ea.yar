rule TTP_XOR_QUAD_CurrentVersionRun_05ea {
  strings:
    $key_05ea = { 56 85 [2] 72 8b [2] 59 a7 [2] 77 85 [2] 63 9e [2] 6c 84 [2] 72 99 [2] 70 98 [2] 6b 9e [2] 77 99 [2] 6b b6 }

  condition:
    any of them
}