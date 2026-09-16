rule TTP_XOR_QUAD_CurrentVersionRun_7f17 {
  strings:
    $key_7f17 = { 2c 78 [2] 08 76 [2] 23 5a [2] 0d 78 [2] 19 63 [2] 16 79 [2] 08 64 [2] 0a 65 [2] 11 63 [2] 0d 64 [2] 11 4b }

  condition:
    any of them
}