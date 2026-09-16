rule TTP_XOR_QUAD_CurrentVersionRun_5e55 {
  strings:
    $key_5e55 = { 0d 3a [2] 29 34 [2] 02 18 [2] 2c 3a [2] 38 21 [2] 37 3b [2] 29 26 [2] 2b 27 [2] 30 21 [2] 2c 26 [2] 30 09 }

  condition:
    any of them
}