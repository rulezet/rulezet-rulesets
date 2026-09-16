rule TTP_XOR_QUAD_CurrentVersionRun_6557 {
  strings:
    $key_6557 = { 36 38 [2] 12 36 [2] 39 1a [2] 17 38 [2] 03 23 [2] 0c 39 [2] 12 24 [2] 10 25 [2] 0b 23 [2] 17 24 [2] 0b 0b }

  condition:
    any of them
}