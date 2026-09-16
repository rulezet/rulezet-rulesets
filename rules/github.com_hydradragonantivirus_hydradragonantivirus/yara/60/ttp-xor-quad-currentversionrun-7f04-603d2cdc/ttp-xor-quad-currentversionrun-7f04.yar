rule TTP_XOR_QUAD_CurrentVersionRun_7f04 {
  strings:
    $key_7f04 = { 2c 6b [2] 08 65 [2] 23 49 [2] 0d 6b [2] 19 70 [2] 16 6a [2] 08 77 [2] 0a 76 [2] 11 70 [2] 0d 77 [2] 11 58 }

  condition:
    any of them
}