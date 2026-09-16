rule TTP_XOR_QUAD_CurrentVersionRun_795b {
  strings:
    $key_795b = { 2a 34 [2] 0e 3a [2] 25 16 [2] 0b 34 [2] 1f 2f [2] 10 35 [2] 0e 28 [2] 0c 29 [2] 17 2f [2] 0b 28 [2] 17 07 }

  condition:
    any of them
}