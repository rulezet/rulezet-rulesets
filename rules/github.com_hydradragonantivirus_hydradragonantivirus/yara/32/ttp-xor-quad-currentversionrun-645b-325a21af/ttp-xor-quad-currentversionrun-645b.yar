rule TTP_XOR_QUAD_CurrentVersionRun_645b {
  strings:
    $key_645b = { 37 34 [2] 13 3a [2] 38 16 [2] 16 34 [2] 02 2f [2] 0d 35 [2] 13 28 [2] 11 29 [2] 0a 2f [2] 16 28 [2] 0a 07 }

  condition:
    any of them
}