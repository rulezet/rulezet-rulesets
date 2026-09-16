rule TTP_XOR_QUAD_CurrentVersionRun_751b {
  strings:
    $key_751b = { 26 74 [2] 02 7a [2] 29 56 [2] 07 74 [2] 13 6f [2] 1c 75 [2] 02 68 [2] 00 69 [2] 1b 6f [2] 07 68 [2] 1b 47 }

  condition:
    any of them
}