rule TTP_XOR_QUAD_CurrentVersionRun_7e5b {
  strings:
    $key_7e5b = { 2d 34 [2] 09 3a [2] 22 16 [2] 0c 34 [2] 18 2f [2] 17 35 [2] 09 28 [2] 0b 29 [2] 10 2f [2] 0c 28 [2] 10 07 }

  condition:
    any of them
}