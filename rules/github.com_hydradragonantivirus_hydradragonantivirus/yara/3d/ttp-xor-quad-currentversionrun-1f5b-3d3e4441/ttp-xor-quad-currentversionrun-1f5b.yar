rule TTP_XOR_QUAD_CurrentVersionRun_1f5b {
  strings:
    $key_1f5b = { 4c 34 [2] 68 3a [2] 43 16 [2] 6d 34 [2] 79 2f [2] 76 35 [2] 68 28 [2] 6a 29 [2] 71 2f [2] 6d 28 [2] 71 07 }

  condition:
    any of them
}