rule TTP_XOR_QUAD_CurrentVersionRun_6c5b {
  strings:
    $key_6c5b = { 3f 34 [2] 1b 3a [2] 30 16 [2] 1e 34 [2] 0a 2f [2] 05 35 [2] 1b 28 [2] 19 29 [2] 02 2f [2] 1e 28 [2] 02 07 }

  condition:
    any of them
}