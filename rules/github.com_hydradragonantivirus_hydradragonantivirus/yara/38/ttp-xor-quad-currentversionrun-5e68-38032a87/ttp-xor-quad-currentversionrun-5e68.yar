rule TTP_XOR_QUAD_CurrentVersionRun_5e68 {
  strings:
    $key_5e68 = { 0d 07 [2] 29 09 [2] 02 25 [2] 2c 07 [2] 38 1c [2] 37 06 [2] 29 1b [2] 2b 1a [2] 30 1c [2] 2c 1b [2] 30 34 }

  condition:
    any of them
}