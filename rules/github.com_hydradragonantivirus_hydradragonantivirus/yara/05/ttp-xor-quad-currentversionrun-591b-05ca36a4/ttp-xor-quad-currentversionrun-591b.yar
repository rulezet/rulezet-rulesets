rule TTP_XOR_QUAD_CurrentVersionRun_591b {
  strings:
    $key_591b = { 0a 74 [2] 2e 7a [2] 05 56 [2] 2b 74 [2] 3f 6f [2] 30 75 [2] 2e 68 [2] 2c 69 [2] 37 6f [2] 2b 68 [2] 37 47 }

  condition:
    any of them
}