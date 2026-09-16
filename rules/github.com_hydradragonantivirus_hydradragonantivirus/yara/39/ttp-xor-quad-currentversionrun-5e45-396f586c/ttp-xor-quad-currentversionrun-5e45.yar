rule TTP_XOR_QUAD_CurrentVersionRun_5e45 {
  strings:
    $key_5e45 = { 0d 2a [2] 29 24 [2] 02 08 [2] 2c 2a [2] 38 31 [2] 37 2b [2] 29 36 [2] 2b 37 [2] 30 31 [2] 2c 36 [2] 30 19 }

  condition:
    any of them
}