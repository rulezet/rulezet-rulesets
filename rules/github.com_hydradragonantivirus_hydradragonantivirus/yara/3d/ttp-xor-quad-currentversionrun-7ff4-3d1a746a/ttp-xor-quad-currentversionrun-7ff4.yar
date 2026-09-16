rule TTP_XOR_QUAD_CurrentVersionRun_7ff4 {
  strings:
    $key_7ff4 = { 2c 9b [2] 08 95 [2] 23 b9 [2] 0d 9b [2] 19 80 [2] 16 9a [2] 08 87 [2] 0a 86 [2] 11 80 [2] 0d 87 [2] 11 a8 }

  condition:
    any of them
}