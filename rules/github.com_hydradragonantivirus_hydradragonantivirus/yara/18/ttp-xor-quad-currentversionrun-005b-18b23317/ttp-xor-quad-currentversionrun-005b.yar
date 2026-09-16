rule TTP_XOR_QUAD_CurrentVersionRun_005b {
  strings:
    $key_005b = { 53 34 [2] 77 3a [2] 5c 16 [2] 72 34 [2] 66 2f [2] 69 35 [2] 77 28 [2] 75 29 [2] 6e 2f [2] 72 28 [2] 6e 07 }

  condition:
    any of them
}