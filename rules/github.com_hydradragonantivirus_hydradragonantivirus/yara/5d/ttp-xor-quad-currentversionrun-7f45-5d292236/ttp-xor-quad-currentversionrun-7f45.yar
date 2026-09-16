rule TTP_XOR_QUAD_CurrentVersionRun_7f45 {
  strings:
    $key_7f45 = { 2c 2a [2] 08 24 [2] 23 08 [2] 0d 2a [2] 19 31 [2] 16 2b [2] 08 36 [2] 0a 37 [2] 11 31 [2] 0d 36 [2] 11 19 }

  condition:
    any of them
}