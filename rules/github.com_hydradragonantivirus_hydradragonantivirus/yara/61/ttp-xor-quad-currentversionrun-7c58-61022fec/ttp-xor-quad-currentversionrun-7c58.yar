rule TTP_XOR_QUAD_CurrentVersionRun_7c58 {
  strings:
    $key_7c58 = { 2f 37 [2] 0b 39 [2] 20 15 [2] 0e 37 [2] 1a 2c [2] 15 36 [2] 0b 2b [2] 09 2a [2] 12 2c [2] 0e 2b [2] 12 04 }

  condition:
    any of them
}