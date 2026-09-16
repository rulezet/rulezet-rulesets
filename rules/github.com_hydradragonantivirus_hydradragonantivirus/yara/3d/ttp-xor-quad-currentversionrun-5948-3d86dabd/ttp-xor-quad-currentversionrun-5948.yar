rule TTP_XOR_QUAD_CurrentVersionRun_5948 {
  strings:
    $key_5948 = { 0a 27 [2] 2e 29 [2] 05 05 [2] 2b 27 [2] 3f 3c [2] 30 26 [2] 2e 3b [2] 2c 3a [2] 37 3c [2] 2b 3b [2] 37 14 }

  condition:
    any of them
}