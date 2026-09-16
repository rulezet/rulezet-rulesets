rule TTP_XOR_QUAD_CurrentVersionRun_6539 {
  strings:
    $key_6539 = { 36 56 [2] 12 58 [2] 39 74 [2] 17 56 [2] 03 4d [2] 0c 57 [2] 12 4a [2] 10 4b [2] 0b 4d [2] 17 4a [2] 0b 65 }

  condition:
    any of them
}