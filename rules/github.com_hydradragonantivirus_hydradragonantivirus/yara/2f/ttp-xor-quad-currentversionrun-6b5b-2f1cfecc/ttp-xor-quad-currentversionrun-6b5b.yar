rule TTP_XOR_QUAD_CurrentVersionRun_6b5b {
  strings:
    $key_6b5b = { 38 34 [2] 1c 3a [2] 37 16 [2] 19 34 [2] 0d 2f [2] 02 35 [2] 1c 28 [2] 1e 29 [2] 05 2f [2] 19 28 [2] 05 07 }

  condition:
    any of them
}