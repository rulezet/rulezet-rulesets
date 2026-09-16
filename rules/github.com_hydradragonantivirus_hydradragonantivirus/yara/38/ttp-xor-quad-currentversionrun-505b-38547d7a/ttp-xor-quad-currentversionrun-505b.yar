rule TTP_XOR_QUAD_CurrentVersionRun_505b {
  strings:
    $key_505b = { 03 34 [2] 27 3a [2] 0c 16 [2] 22 34 [2] 36 2f [2] 39 35 [2] 27 28 [2] 25 29 [2] 3e 2f [2] 22 28 [2] 3e 07 }

  condition:
    any of them
}