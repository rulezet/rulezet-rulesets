rule TTP_XOR_QUAD_CurrentVersionRun_365b {
  strings:
    $key_365b = { 65 34 [2] 41 3a [2] 6a 16 [2] 44 34 [2] 50 2f [2] 5f 35 [2] 41 28 [2] 43 29 [2] 58 2f [2] 44 28 [2] 58 07 }

  condition:
    any of them
}