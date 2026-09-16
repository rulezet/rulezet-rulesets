rule TTP_XOR_QUAD_CurrentVersionRun_f0ea {
  strings:
    $key_f0ea = { a3 85 [2] 87 8b [2] ac a7 [2] 82 85 [2] 96 9e [2] 99 84 [2] 87 99 [2] 85 98 [2] 9e 9e [2] 82 99 [2] 9e b6 }

  condition:
    any of them
}