rule TTP_XOR_QUAD_CurrentVersionRun_6555 {
  strings:
    $key_6555 = { 36 3a [2] 12 34 [2] 39 18 [2] 17 3a [2] 03 21 [2] 0c 3b [2] 12 26 [2] 10 27 [2] 0b 21 [2] 17 26 [2] 0b 09 }

  condition:
    any of them
}