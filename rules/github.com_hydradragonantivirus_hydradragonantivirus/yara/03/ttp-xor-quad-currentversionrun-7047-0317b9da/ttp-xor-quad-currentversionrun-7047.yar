rule TTP_XOR_QUAD_CurrentVersionRun_7047 {
  strings:
    $key_7047 = { 23 28 [2] 07 26 [2] 2c 0a [2] 02 28 [2] 16 33 [2] 19 29 [2] 07 34 [2] 05 35 [2] 1e 33 [2] 02 34 [2] 1e 1b }

  condition:
    any of them
}