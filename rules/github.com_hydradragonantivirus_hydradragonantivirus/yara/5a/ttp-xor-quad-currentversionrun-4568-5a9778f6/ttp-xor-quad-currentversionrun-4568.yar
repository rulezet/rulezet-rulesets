rule TTP_XOR_QUAD_CurrentVersionRun_4568 {
  strings:
    $key_4568 = { 16 07 [2] 32 09 [2] 19 25 [2] 37 07 [2] 23 1c [2] 2c 06 [2] 32 1b [2] 30 1a [2] 2b 1c [2] 37 1b [2] 2b 34 }

  condition:
    any of them
}