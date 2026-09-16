rule TTP_XOR_QUAD_CurrentVersionRun_5247 {
  strings:
    $key_5247 = { 01 28 [2] 25 26 [2] 0e 0a [2] 20 28 [2] 34 33 [2] 3b 29 [2] 25 34 [2] 27 35 [2] 3c 33 [2] 20 34 [2] 3c 1b }

  condition:
    any of them
}