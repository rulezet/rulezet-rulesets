rule TTP_XOR_QUAD_CurrentVersionRun_1d47 {
  strings:
    $key_1d47 = { 4e 28 [2] 6a 26 [2] 41 0a [2] 6f 28 [2] 7b 33 [2] 74 29 [2] 6a 34 [2] 68 35 [2] 73 33 [2] 6f 34 [2] 73 1b }

  condition:
    any of them
}