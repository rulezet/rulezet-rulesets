rule TTP_XOR_QUAD_CurrentVersionRun_7f55 {
  strings:
    $key_7f55 = { 2c 3a [2] 08 34 [2] 23 18 [2] 0d 3a [2] 19 21 [2] 16 3b [2] 08 26 [2] 0a 27 [2] 11 21 [2] 0d 26 [2] 11 09 }

  condition:
    any of them
}