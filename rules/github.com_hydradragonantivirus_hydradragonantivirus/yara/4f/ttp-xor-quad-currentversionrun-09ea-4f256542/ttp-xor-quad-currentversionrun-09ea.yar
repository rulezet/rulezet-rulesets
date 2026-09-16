rule TTP_XOR_QUAD_CurrentVersionRun_09ea {
  strings:
    $key_09ea = { 5a 85 [2] 7e 8b [2] 55 a7 [2] 7b 85 [2] 6f 9e [2] 60 84 [2] 7e 99 [2] 7c 98 [2] 67 9e [2] 7b 99 [2] 67 b6 }

  condition:
    any of them
}