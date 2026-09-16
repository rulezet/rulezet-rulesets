rule TTP_XOR_QUAD_CurrentVersionRun_5e36 {
  strings:
    $key_5e36 = { 0d 59 [2] 29 57 [2] 02 7b [2] 2c 59 [2] 38 42 [2] 37 58 [2] 29 45 [2] 2b 44 [2] 30 42 [2] 2c 45 [2] 30 6a }

  condition:
    any of them
}