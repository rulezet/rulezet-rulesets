rule TTP_XOR_QUAD_CurrentVersionRun_4d1b {
  strings:
    $key_4d1b = { 1e 74 [2] 3a 7a [2] 11 56 [2] 3f 74 [2] 2b 6f [2] 24 75 [2] 3a 68 [2] 38 69 [2] 23 6f [2] 3f 68 [2] 23 47 }

  condition:
    any of them
}