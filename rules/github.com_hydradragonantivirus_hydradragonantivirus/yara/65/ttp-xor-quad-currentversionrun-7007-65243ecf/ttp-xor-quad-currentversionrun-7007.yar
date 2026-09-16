rule TTP_XOR_QUAD_CurrentVersionRun_7007 {
  strings:
    $key_7007 = { 23 68 [2] 07 66 [2] 2c 4a [2] 02 68 [2] 16 73 [2] 19 69 [2] 07 74 [2] 05 75 [2] 1e 73 [2] 02 74 [2] 1e 5b }

  condition:
    any of them
}