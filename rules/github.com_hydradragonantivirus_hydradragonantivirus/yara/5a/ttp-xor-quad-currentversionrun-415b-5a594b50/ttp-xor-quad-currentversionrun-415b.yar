rule TTP_XOR_QUAD_CurrentVersionRun_415b {
  strings:
    $key_415b = { 12 34 [2] 36 3a [2] 1d 16 [2] 33 34 [2] 27 2f [2] 28 35 [2] 36 28 [2] 34 29 [2] 2f 2f [2] 33 28 [2] 2f 07 }

  condition:
    any of them
}