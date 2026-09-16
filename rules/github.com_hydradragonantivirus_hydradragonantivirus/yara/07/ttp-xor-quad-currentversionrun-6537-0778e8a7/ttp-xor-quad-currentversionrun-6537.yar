rule TTP_XOR_QUAD_CurrentVersionRun_6537 {
  strings:
    $key_6537 = { 36 58 [2] 12 56 [2] 39 7a [2] 17 58 [2] 03 43 [2] 0c 59 [2] 12 44 [2] 10 45 [2] 0b 43 [2] 17 44 [2] 0b 6b }

  condition:
    any of them
}