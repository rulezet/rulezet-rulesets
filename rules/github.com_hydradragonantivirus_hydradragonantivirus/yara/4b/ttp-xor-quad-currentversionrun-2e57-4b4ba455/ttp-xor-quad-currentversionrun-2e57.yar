rule TTP_XOR_QUAD_CurrentVersionRun_2e57 {
  strings:
    $key_2e57 = { 7d 38 [2] 59 36 [2] 72 1a [2] 5c 38 [2] 48 23 [2] 47 39 [2] 59 24 [2] 5b 25 [2] 40 23 [2] 5c 24 [2] 40 0b }

  condition:
    any of them
}