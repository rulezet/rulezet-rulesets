rule TTP_XOR_QUAD_CurrentVersionRun_2247 {
  strings:
    $key_2247 = { 71 28 [2] 55 26 [2] 7e 0a [2] 50 28 [2] 44 33 [2] 4b 29 [2] 55 34 [2] 57 35 [2] 4c 33 [2] 50 34 [2] 4c 1b }

  condition:
    any of them
}