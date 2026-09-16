rule TTP_XOR_QUAD_CurrentVersionRun_4d17 {
  strings:
    $key_4d17 = { 1e 78 [2] 3a 76 [2] 11 5a [2] 3f 78 [2] 2b 63 [2] 24 79 [2] 3a 64 [2] 38 65 [2] 23 63 [2] 3f 64 [2] 23 4b }

  condition:
    any of them
}