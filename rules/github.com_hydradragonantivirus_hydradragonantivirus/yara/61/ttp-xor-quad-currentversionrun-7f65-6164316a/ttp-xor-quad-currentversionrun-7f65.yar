rule TTP_XOR_QUAD_CurrentVersionRun_7f65 {
  strings:
    $key_7f65 = { 2c 0a [2] 08 04 [2] 23 28 [2] 0d 0a [2] 19 11 [2] 16 0b [2] 08 16 [2] 0a 17 [2] 11 11 [2] 0d 16 [2] 11 39 }

  condition:
    any of them
}