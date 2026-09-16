rule TTP_XOR_QUAD_CurrentVersionRun_3457 {
  strings:
    $key_3457 = { 67 38 [2] 43 36 [2] 68 1a [2] 46 38 [2] 52 23 [2] 5d 39 [2] 43 24 [2] 41 25 [2] 5a 23 [2] 46 24 [2] 5a 0b }

  condition:
    any of them
}