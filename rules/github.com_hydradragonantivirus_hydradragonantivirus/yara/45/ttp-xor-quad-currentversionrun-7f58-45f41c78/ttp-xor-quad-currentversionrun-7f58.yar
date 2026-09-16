rule TTP_XOR_QUAD_CurrentVersionRun_7f58 {
  strings:
    $key_7f58 = { 2c 37 [2] 08 39 [2] 23 15 [2] 0d 37 [2] 19 2c [2] 16 36 [2] 08 2b [2] 0a 2a [2] 11 2c [2] 0d 2b [2] 11 04 }

  condition:
    any of them
}