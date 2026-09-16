rule TTP_XOR_QUAD_CurrentVersionRun_4d07 {
  strings:
    $key_4d07 = { 1e 68 [2] 3a 66 [2] 11 4a [2] 3f 68 [2] 2b 73 [2] 24 69 [2] 3a 74 [2] 38 75 [2] 23 73 [2] 3f 74 [2] 23 5b }

  condition:
    any of them
}