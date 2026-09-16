rule TTP_XOR_QUAD_CurrentVersionRun_4d79 {
  strings:
    $key_4d79 = { 1e 16 [2] 3a 18 [2] 11 34 [2] 3f 16 [2] 2b 0d [2] 24 17 [2] 3a 0a [2] 38 0b [2] 23 0d [2] 3f 0a [2] 23 25 }

  condition:
    any of them
}