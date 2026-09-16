rule TTP_XOR_QUAD_CurrentVersionRun_4274 {
  strings:
    $key_4274 = { 11 1b [2] 35 15 [2] 1e 39 [2] 30 1b [2] 24 00 [2] 2b 1a [2] 35 07 [2] 37 06 [2] 2c 00 [2] 30 07 [2] 2c 28 }

  condition:
    any of them
}