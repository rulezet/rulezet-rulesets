rule TTP_XOR_QUAD_CurrentVersionRun_3b5b {
  strings:
    $key_3b5b = { 68 34 [2] 4c 3a [2] 67 16 [2] 49 34 [2] 5d 2f [2] 52 35 [2] 4c 28 [2] 4e 29 [2] 55 2f [2] 49 28 [2] 55 07 }

  condition:
    any of them
}