rule TTP_XOR_QUAD_CurrentVersionRun_5965 {
  strings:
    $key_5965 = { 0a 0a [2] 2e 04 [2] 05 28 [2] 2b 0a [2] 3f 11 [2] 30 0b [2] 2e 16 [2] 2c 17 [2] 37 11 [2] 2b 16 [2] 37 39 }

  condition:
    any of them
}