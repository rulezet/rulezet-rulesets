rule TTP_XOR_QUAD_CurrentVersionRun_7539 {
  strings:
    $key_7539 = { 26 56 [2] 02 58 [2] 29 74 [2] 07 56 [2] 13 4d [2] 1c 57 [2] 02 4a [2] 00 4b [2] 1b 4d [2] 07 4a [2] 1b 65 }

  condition:
    any of them
}