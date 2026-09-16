rule TTP_XOR_QUAD_CurrentVersionRun_5967 {
  strings:
    $key_5967 = { 0a 08 [2] 2e 06 [2] 05 2a [2] 2b 08 [2] 3f 13 [2] 30 09 [2] 2e 14 [2] 2c 15 [2] 37 13 [2] 2b 14 [2] 37 3b }

  condition:
    any of them
}