rule TTP_XOR_QUAD_CurrentVersionRun_5dea {
  strings:
    $key_5dea = { 0e 85 [2] 2a 8b [2] 01 a7 [2] 2f 85 [2] 3b 9e [2] 34 84 [2] 2a 99 [2] 28 98 [2] 33 9e [2] 2f 99 [2] 33 b6 }

  condition:
    any of them
}