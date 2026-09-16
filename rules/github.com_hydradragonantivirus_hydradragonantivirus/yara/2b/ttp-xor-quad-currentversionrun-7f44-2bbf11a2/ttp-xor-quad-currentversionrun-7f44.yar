rule TTP_XOR_QUAD_CurrentVersionRun_7f44 {
  strings:
    $key_7f44 = { 2c 2b [2] 08 25 [2] 23 09 [2] 0d 2b [2] 19 30 [2] 16 2a [2] 08 37 [2] 0a 36 [2] 11 30 [2] 0d 37 [2] 11 18 }

  condition:
    any of them
}