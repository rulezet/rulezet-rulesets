rule TTP_XOR_QUAD_CurrentVersionRun_1657 {
  strings:
    $key_1657 = { 45 38 [2] 61 36 [2] 4a 1a [2] 64 38 [2] 70 23 [2] 7f 39 [2] 61 24 [2] 63 25 [2] 78 23 [2] 64 24 [2] 78 0b }

  condition:
    any of them
}