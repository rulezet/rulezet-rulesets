rule TTP_XOR_QUAD_CurrentVersionRun_5f5b {
  strings:
    $key_5f5b = { 0c 34 [2] 28 3a [2] 03 16 [2] 2d 34 [2] 39 2f [2] 36 35 [2] 28 28 [2] 2a 29 [2] 31 2f [2] 2d 28 [2] 31 07 }

  condition:
    any of them
}