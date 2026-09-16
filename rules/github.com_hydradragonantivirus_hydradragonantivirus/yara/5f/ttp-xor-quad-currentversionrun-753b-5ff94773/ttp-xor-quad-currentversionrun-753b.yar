rule TTP_XOR_QUAD_CurrentVersionRun_753b {
  strings:
    $key_753b = { 26 54 [2] 02 5a [2] 29 76 [2] 07 54 [2] 13 4f [2] 1c 55 [2] 02 48 [2] 00 49 [2] 1b 4f [2] 07 48 [2] 1b 67 }

  condition:
    any of them
}