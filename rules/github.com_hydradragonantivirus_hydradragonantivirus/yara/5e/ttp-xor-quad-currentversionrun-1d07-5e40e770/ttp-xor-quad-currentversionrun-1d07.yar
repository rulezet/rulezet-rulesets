rule TTP_XOR_QUAD_CurrentVersionRun_1d07 {
  strings:
    $key_1d07 = { 4e 68 [2] 6a 66 [2] 41 4a [2] 6f 68 [2] 7b 73 [2] 74 69 [2] 6a 74 [2] 68 75 [2] 73 73 [2] 6f 74 [2] 73 5b }

  condition:
    any of them
}