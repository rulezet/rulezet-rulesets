rule TTP_XOR_QUAD_CurrentVersionRun_7558 {
  strings:
    $key_7558 = { 26 37 [2] 02 39 [2] 29 15 [2] 07 37 [2] 13 2c [2] 1c 36 [2] 02 2b [2] 00 2a [2] 1b 2c [2] 07 2b [2] 1b 04 }

  condition:
    any of them
}