rule TTP_XOR_QUAD_CurrentVersionRun_2b5b {
  strings:
    $key_2b5b = { 78 34 [2] 5c 3a [2] 77 16 [2] 59 34 [2] 4d 2f [2] 42 35 [2] 5c 28 [2] 5e 29 [2] 45 2f [2] 59 28 [2] 45 07 }

  condition:
    any of them
}