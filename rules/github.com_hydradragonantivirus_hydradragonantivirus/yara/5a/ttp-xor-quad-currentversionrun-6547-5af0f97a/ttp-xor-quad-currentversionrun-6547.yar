rule TTP_XOR_QUAD_CurrentVersionRun_6547 {
  strings:
    $key_6547 = { 36 28 [2] 12 26 [2] 39 0a [2] 17 28 [2] 03 33 [2] 0c 29 [2] 12 34 [2] 10 35 [2] 0b 33 [2] 17 34 [2] 0b 1b }

  condition:
    any of them
}