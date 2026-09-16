rule TTP_XOR_QUAD_CurrentVersionRun_4c5b {
  strings:
    $key_4c5b = { 1f 34 [2] 3b 3a [2] 10 16 [2] 3e 34 [2] 2a 2f [2] 25 35 [2] 3b 28 [2] 39 29 [2] 22 2f [2] 3e 28 [2] 22 07 }

  condition:
    any of them
}