rule TTP_XOR_QUAD_CurrentVersionRun_7537 {
  strings:
    $key_7537 = { 26 58 [2] 02 56 [2] 29 7a [2] 07 58 [2] 13 43 [2] 1c 59 [2] 02 44 [2] 00 45 [2] 1b 43 [2] 07 44 [2] 1b 6b }

  condition:
    any of them
}