rule TTP_XOR_QUAD_CurrentVersionRun_5e48 {
  strings:
    $key_5e48 = { 0d 27 [2] 29 29 [2] 02 05 [2] 2c 27 [2] 38 3c [2] 37 26 [2] 29 3b [2] 2b 3a [2] 30 3c [2] 2c 3b [2] 30 14 }

  condition:
    any of them
}