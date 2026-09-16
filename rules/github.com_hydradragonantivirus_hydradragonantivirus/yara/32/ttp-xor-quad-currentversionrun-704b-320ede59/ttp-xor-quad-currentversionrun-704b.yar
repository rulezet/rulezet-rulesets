rule TTP_XOR_QUAD_CurrentVersionRun_704b {
  strings:
    $key_704b = { 23 24 [2] 07 2a [2] 2c 06 [2] 02 24 [2] 16 3f [2] 19 25 [2] 07 38 [2] 05 39 [2] 1e 3f [2] 02 38 [2] 1e 17 }

  condition:
    any of them
}