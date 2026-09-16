rule TTP_XOR_QUAD_CurrentVersionRun_6c58 {
  strings:
    $key_6c58 = { 3f 37 [2] 1b 39 [2] 30 15 [2] 1e 37 [2] 0a 2c [2] 05 36 [2] 1b 2b [2] 19 2a [2] 02 2c [2] 1e 2b [2] 02 04 }

  condition:
    any of them
}