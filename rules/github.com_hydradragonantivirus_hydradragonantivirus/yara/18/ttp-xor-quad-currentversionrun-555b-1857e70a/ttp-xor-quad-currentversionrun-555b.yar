rule TTP_XOR_QUAD_CurrentVersionRun_555b {
  strings:
    $key_555b = { 06 34 [2] 22 3a [2] 09 16 [2] 27 34 [2] 33 2f [2] 3c 35 [2] 22 28 [2] 20 29 [2] 3b 2f [2] 27 28 [2] 3b 07 }

  condition:
    any of them
}