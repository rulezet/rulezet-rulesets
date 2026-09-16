rule TTP_XOR_QUAD_CurrentVersionRun_5958 {
  strings:
    $key_5958 = { 0a 37 [2] 2e 39 [2] 05 15 [2] 2b 37 [2] 3f 2c [2] 30 36 [2] 2e 2b [2] 2c 2a [2] 37 2c [2] 2b 2b [2] 37 04 }

  condition:
    any of them
}