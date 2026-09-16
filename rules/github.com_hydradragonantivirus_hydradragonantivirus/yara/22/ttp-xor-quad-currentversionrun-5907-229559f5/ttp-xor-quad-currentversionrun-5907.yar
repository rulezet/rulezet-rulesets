rule TTP_XOR_QUAD_CurrentVersionRun_5907 {
  strings:
    $key_5907 = { 0a 68 [2] 2e 66 [2] 05 4a [2] 2b 68 [2] 3f 73 [2] 30 69 [2] 2e 74 [2] 2c 75 [2] 37 73 [2] 2b 74 [2] 37 5b }

  condition:
    any of them
}