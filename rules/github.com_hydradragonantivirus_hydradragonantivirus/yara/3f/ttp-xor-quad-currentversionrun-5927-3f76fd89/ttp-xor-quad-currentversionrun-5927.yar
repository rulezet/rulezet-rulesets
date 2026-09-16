rule TTP_XOR_QUAD_CurrentVersionRun_5927 {
  strings:
    $key_5927 = { 0a 48 [2] 2e 46 [2] 05 6a [2] 2b 48 [2] 3f 53 [2] 30 49 [2] 2e 54 [2] 2c 55 [2] 37 53 [2] 2b 54 [2] 37 7b }

  condition:
    any of them
}