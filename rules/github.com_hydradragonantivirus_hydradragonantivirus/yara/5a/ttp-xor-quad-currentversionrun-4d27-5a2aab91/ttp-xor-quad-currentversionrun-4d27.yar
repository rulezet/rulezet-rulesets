rule TTP_XOR_QUAD_CurrentVersionRun_4d27 {
  strings:
    $key_4d27 = { 1e 48 [2] 3a 46 [2] 11 6a [2] 3f 48 [2] 2b 53 [2] 24 49 [2] 3a 54 [2] 38 55 [2] 23 53 [2] 3f 54 [2] 23 7b }

  condition:
    any of them
}