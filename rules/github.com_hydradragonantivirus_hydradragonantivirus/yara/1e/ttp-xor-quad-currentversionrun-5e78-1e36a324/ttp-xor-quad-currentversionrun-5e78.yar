rule TTP_XOR_QUAD_CurrentVersionRun_5e78 {
  strings:
    $key_5e78 = { 0d 17 [2] 29 19 [2] 02 35 [2] 2c 17 [2] 38 0c [2] 37 16 [2] 29 0b [2] 2b 0a [2] 30 0c [2] 2c 0b [2] 30 24 }

  condition:
    any of them
}