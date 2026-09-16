rule TTP_XOR_QUAD_CurrentVersionRun_f6ea {
  strings:
    $key_f6ea = { a5 85 [2] 81 8b [2] aa a7 [2] 84 85 [2] 90 9e [2] 9f 84 [2] 81 99 [2] 83 98 [2] 98 9e [2] 84 99 [2] 98 b6 }

  condition:
    any of them
}