rule TTP_XOR_QUAD_CurrentVersionRun_6858 {
  strings:
    $key_6858 = { 3b 37 [2] 1f 39 [2] 34 15 [2] 1a 37 [2] 0e 2c [2] 01 36 [2] 1f 2b [2] 1d 2a [2] 06 2c [2] 1a 2b [2] 06 04 }

  condition:
    any of them
}