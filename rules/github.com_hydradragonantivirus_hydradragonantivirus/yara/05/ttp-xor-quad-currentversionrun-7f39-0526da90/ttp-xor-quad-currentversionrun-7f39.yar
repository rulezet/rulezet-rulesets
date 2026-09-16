rule TTP_XOR_QUAD_CurrentVersionRun_7f39 {
  strings:
    $key_7f39 = { 2c 56 [2] 08 58 [2] 23 74 [2] 0d 56 [2] 19 4d [2] 16 57 [2] 08 4a [2] 0a 4b [2] 11 4d [2] 0d 4a [2] 11 65 }

  condition:
    any of them
}