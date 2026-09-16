rule TTP_XOR_QUAD_CurrentVersionRun_7f79 {
  strings:
    $key_7f79 = { 2c 16 [2] 08 18 [2] 23 34 [2] 0d 16 [2] 19 0d [2] 16 17 [2] 08 0a [2] 0a 0b [2] 11 0d [2] 0d 0a [2] 11 25 }

  condition:
    any of them
}