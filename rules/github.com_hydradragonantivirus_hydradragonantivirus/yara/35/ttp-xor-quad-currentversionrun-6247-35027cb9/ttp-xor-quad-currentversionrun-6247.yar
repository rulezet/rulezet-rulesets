rule TTP_XOR_QUAD_CurrentVersionRun_6247 {
  strings:
    $key_6247 = { 31 28 [2] 15 26 [2] 3e 0a [2] 10 28 [2] 04 33 [2] 0b 29 [2] 15 34 [2] 17 35 [2] 0c 33 [2] 10 34 [2] 0c 1b }

  condition:
    any of them
}