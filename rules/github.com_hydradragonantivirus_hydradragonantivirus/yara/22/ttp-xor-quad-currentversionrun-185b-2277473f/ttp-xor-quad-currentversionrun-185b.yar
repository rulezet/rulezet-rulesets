rule TTP_XOR_QUAD_CurrentVersionRun_185b {
  strings:
    $key_185b = { 4b 34 [2] 6f 3a [2] 44 16 [2] 6a 34 [2] 7e 2f [2] 71 35 [2] 6f 28 [2] 6d 29 [2] 76 2f [2] 6a 28 [2] 76 07 }

  condition:
    any of them
}