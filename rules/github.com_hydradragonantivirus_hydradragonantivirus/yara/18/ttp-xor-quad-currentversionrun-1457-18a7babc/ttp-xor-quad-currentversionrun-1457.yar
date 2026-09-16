rule TTP_XOR_QUAD_CurrentVersionRun_1457 {
  strings:
    $key_1457 = { 47 38 [2] 63 36 [2] 48 1a [2] 66 38 [2] 72 23 [2] 7d 39 [2] 63 24 [2] 61 25 [2] 7a 23 [2] 66 24 [2] 7a 0b }

  condition:
    any of them
}