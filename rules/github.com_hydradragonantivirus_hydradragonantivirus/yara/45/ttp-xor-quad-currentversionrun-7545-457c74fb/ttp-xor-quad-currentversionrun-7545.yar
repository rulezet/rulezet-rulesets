rule TTP_XOR_QUAD_CurrentVersionRun_7545 {
  strings:
    $key_7545 = { 26 2a [2] 02 24 [2] 29 08 [2] 07 2a [2] 13 31 [2] 1c 2b [2] 02 36 [2] 00 37 [2] 1b 31 [2] 07 36 [2] 1b 19 }

  condition:
    any of them
}