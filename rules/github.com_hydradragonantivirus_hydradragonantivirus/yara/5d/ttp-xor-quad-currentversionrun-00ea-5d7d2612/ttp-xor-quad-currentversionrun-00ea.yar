rule TTP_XOR_QUAD_CurrentVersionRun_00ea {
  strings:
    $key_00ea = { 53 85 [2] 77 8b [2] 5c a7 [2] 72 85 [2] 66 9e [2] 69 84 [2] 77 99 [2] 75 98 [2] 6e 9e [2] 72 99 [2] 6e b6 }

  condition:
    any of them
}