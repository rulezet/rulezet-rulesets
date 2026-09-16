rule TTP_XOR_QUAD_CurrentVersionRun_5d47 {
  strings:
    $key_5d47 = { 0e 28 [2] 2a 26 [2] 01 0a [2] 2f 28 [2] 3b 33 [2] 34 29 [2] 2a 34 [2] 28 35 [2] 33 33 [2] 2f 34 [2] 33 1b }

  condition:
    any of them
}