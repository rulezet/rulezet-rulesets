rule TTP_XOR_QUAD_CurrentVersionRun_395b {
  strings:
    $key_395b = { 6a 34 [2] 4e 3a [2] 65 16 [2] 4b 34 [2] 5f 2f [2] 50 35 [2] 4e 28 [2] 4c 29 [2] 57 2f [2] 4b 28 [2] 57 07 }

  condition:
    any of them
}