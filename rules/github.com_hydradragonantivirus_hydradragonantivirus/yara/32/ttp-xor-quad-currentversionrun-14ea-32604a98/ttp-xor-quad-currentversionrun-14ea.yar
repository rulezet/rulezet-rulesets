rule TTP_XOR_QUAD_CurrentVersionRun_14ea {
  strings:
    $key_14ea = { 47 85 [2] 63 8b [2] 48 a7 [2] 66 85 [2] 72 9e [2] 7d 84 [2] 63 99 [2] 61 98 [2] 7a 9e [2] 66 99 [2] 7a b6 }

  condition:
    any of them
}