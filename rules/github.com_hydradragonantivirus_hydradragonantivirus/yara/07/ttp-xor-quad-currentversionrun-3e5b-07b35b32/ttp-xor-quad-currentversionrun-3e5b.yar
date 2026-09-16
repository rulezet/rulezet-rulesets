rule TTP_XOR_QUAD_CurrentVersionRun_3e5b {
  strings:
    $key_3e5b = { 6d 34 [2] 49 3a [2] 62 16 [2] 4c 34 [2] 58 2f [2] 57 35 [2] 49 28 [2] 4b 29 [2] 50 2f [2] 4c 28 [2] 50 07 }

  condition:
    any of them
}