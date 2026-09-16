rule TTP_XOR_QUAD_CurrentVersionRun_6579 {
  strings:
    $key_6579 = { 36 16 [2] 12 18 [2] 39 34 [2] 17 16 [2] 03 0d [2] 0c 17 [2] 12 0a [2] 10 0b [2] 0b 0d [2] 17 0a [2] 0b 25 }

  condition:
    any of them
}