rule TTP_XOR_QUAD_CurrentVersionRun_4c57 {
  strings:
    $key_4c57 = { 1f 38 [2] 3b 36 [2] 10 1a [2] 3e 38 [2] 2a 23 [2] 25 39 [2] 3b 24 [2] 39 25 [2] 22 23 [2] 3e 24 [2] 22 0b }

  condition:
    any of them
}