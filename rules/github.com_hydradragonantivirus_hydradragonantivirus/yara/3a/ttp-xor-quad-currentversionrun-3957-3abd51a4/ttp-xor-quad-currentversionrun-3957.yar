rule TTP_XOR_QUAD_CurrentVersionRun_3957 {
  strings:
    $key_3957 = { 6a 38 [2] 4e 36 [2] 65 1a [2] 4b 38 [2] 5f 23 [2] 50 39 [2] 4e 24 [2] 4c 25 [2] 57 23 [2] 4b 24 [2] 57 0b }

  condition:
    any of them
}