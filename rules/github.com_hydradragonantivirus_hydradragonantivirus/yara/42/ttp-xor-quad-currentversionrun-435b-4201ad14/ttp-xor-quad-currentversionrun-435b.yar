rule TTP_XOR_QUAD_CurrentVersionRun_435b {
  strings:
    $key_435b = { 10 34 [2] 34 3a [2] 1f 16 [2] 31 34 [2] 25 2f [2] 2a 35 [2] 34 28 [2] 36 29 [2] 2d 2f [2] 31 28 [2] 2d 07 }

  condition:
    any of them
}