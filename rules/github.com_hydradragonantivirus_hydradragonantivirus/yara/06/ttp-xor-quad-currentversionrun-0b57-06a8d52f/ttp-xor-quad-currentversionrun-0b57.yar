rule TTP_XOR_QUAD_CurrentVersionRun_0b57 {
  strings:
    $key_0b57 = { 58 38 [2] 7c 36 [2] 57 1a [2] 79 38 [2] 6d 23 [2] 62 39 [2] 7c 24 [2] 7e 25 [2] 65 23 [2] 79 24 [2] 65 0b }

  condition:
    any of them
}