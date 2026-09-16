rule TTP_XOR_QUAD_CurrentVersionRun_24ea {
  strings:
    $key_24ea = { 77 85 [2] 53 8b [2] 78 a7 [2] 56 85 [2] 42 9e [2] 4d 84 [2] 53 99 [2] 51 98 [2] 4a 9e [2] 56 99 [2] 4a b6 }

  condition:
    any of them
}