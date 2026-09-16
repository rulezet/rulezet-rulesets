rule TTP_XOR_QUAD_CurrentVersionRun_1e5b {
  strings:
    $key_1e5b = { 4d 34 [2] 69 3a [2] 42 16 [2] 6c 34 [2] 78 2f [2] 77 35 [2] 69 28 [2] 6b 29 [2] 70 2f [2] 6c 28 [2] 70 07 }

  condition:
    any of them
}