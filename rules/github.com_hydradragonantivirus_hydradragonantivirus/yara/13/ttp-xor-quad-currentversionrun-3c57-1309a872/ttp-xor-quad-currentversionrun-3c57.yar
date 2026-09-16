rule TTP_XOR_QUAD_CurrentVersionRun_3c57 {
  strings:
    $key_3c57 = { 6f 38 [2] 4b 36 [2] 60 1a [2] 4e 38 [2] 5a 23 [2] 55 39 [2] 4b 24 [2] 49 25 [2] 52 23 [2] 4e 24 [2] 52 0b }

  condition:
    any of them
}