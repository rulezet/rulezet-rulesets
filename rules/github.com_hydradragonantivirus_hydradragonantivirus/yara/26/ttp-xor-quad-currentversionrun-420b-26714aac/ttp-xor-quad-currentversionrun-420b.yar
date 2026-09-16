rule TTP_XOR_QUAD_CurrentVersionRun_420b {
  strings:
    $key_420b = { 11 64 [2] 35 6a [2] 1e 46 [2] 30 64 [2] 24 7f [2] 2b 65 [2] 35 78 [2] 37 79 [2] 2c 7f [2] 30 78 [2] 2c 57 }

  condition:
    any of them
}