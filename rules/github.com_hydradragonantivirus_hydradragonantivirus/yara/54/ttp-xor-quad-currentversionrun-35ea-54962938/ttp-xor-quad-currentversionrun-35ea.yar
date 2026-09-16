rule TTP_XOR_QUAD_CurrentVersionRun_35ea {
  strings:
    $key_35ea = { 66 85 [2] 42 8b [2] 69 a7 [2] 47 85 [2] 53 9e [2] 5c 84 [2] 42 99 [2] 40 98 [2] 5b 9e [2] 47 99 [2] 5b b6 }

  condition:
    any of them
}