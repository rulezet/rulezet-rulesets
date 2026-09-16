rule TTP_XOR_QUAD_CurrentVersionRun_454b {
  strings:
    $key_454b = { 16 24 [2] 32 2a [2] 19 06 [2] 37 24 [2] 23 3f [2] 2c 25 [2] 32 38 [2] 30 39 [2] 2b 3f [2] 37 38 [2] 2b 17 }

  condition:
    any of them
}