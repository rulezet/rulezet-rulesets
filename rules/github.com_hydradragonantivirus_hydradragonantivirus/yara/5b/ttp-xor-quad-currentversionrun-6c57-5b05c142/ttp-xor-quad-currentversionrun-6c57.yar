rule TTP_XOR_QUAD_CurrentVersionRun_6c57 {
  strings:
    $key_6c57 = { 3f 38 [2] 1b 36 [2] 30 1a [2] 1e 38 [2] 0a 23 [2] 05 39 [2] 1b 24 [2] 19 25 [2] 02 23 [2] 1e 24 [2] 02 0b }

  condition:
    any of them
}