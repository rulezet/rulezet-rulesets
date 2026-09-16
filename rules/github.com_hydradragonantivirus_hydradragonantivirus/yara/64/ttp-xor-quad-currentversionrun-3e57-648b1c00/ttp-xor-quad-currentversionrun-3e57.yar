rule TTP_XOR_QUAD_CurrentVersionRun_3e57 {
  strings:
    $key_3e57 = { 6d 38 [2] 49 36 [2] 62 1a [2] 4c 38 [2] 58 23 [2] 57 39 [2] 49 24 [2] 4b 25 [2] 50 23 [2] 4c 24 [2] 50 0b }

  condition:
    any of them
}