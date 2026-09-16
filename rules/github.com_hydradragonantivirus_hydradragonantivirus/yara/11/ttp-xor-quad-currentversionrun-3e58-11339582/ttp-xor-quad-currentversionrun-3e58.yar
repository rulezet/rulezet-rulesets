rule TTP_XOR_QUAD_CurrentVersionRun_3e58 {
  strings:
    $key_3e58 = { 6d 37 [2] 49 39 [2] 62 15 [2] 4c 37 [2] 58 2c [2] 57 36 [2] 49 2b [2] 4b 2a [2] 50 2c [2] 4c 2b [2] 50 04 }

  condition:
    any of them
}