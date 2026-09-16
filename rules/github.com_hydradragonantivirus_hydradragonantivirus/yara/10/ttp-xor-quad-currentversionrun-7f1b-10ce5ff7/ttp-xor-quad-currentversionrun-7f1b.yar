rule TTP_XOR_QUAD_CurrentVersionRun_7f1b {
  strings:
    $key_7f1b = { 2c 74 [2] 08 7a [2] 23 56 [2] 0d 74 [2] 19 6f [2] 16 75 [2] 08 68 [2] 0a 69 [2] 11 6f [2] 0d 68 [2] 11 47 }

  condition:
    any of them
}