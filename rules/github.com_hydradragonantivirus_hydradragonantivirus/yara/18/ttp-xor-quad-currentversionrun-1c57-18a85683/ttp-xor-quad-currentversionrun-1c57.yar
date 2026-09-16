rule TTP_XOR_QUAD_CurrentVersionRun_1c57 {
  strings:
    $key_1c57 = { 4f 38 [2] 6b 36 [2] 40 1a [2] 6e 38 [2] 7a 23 [2] 75 39 [2] 6b 24 [2] 69 25 [2] 72 23 [2] 6e 24 [2] 72 0b }

  condition:
    any of them
}