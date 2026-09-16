rule TTP_XOR_QUAD_CurrentVersionRun_2dea {
  strings:
    $key_2dea = { 7e 85 [2] 5a 8b [2] 71 a7 [2] 5f 85 [2] 4b 9e [2] 44 84 [2] 5a 99 [2] 58 98 [2] 43 9e [2] 5f 99 [2] 43 b6 }

  condition:
    any of them
}