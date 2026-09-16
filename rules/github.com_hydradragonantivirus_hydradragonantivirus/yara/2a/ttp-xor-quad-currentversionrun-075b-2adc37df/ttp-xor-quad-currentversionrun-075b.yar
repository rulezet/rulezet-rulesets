rule TTP_XOR_QUAD_CurrentVersionRun_075b {
  strings:
    $key_075b = { 54 34 [2] 70 3a [2] 5b 16 [2] 75 34 [2] 61 2f [2] 6e 35 [2] 70 28 [2] 72 29 [2] 69 2f [2] 75 28 [2] 69 07 }

  condition:
    any of them
}