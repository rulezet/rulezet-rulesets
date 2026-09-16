rule TTP_XOR_QUAD_CurrentVersionRun_7b5b {
  strings:
    $key_7b5b = { 28 34 [2] 0c 3a [2] 27 16 [2] 09 34 [2] 1d 2f [2] 12 35 [2] 0c 28 [2] 0e 29 [2] 15 2f [2] 09 28 [2] 15 07 }

  condition:
    any of them
}