rule TTP_XOR_QUAD_CurrentVersionRun_7548 {
  strings:
    $key_7548 = { 26 27 [2] 02 29 [2] 29 05 [2] 07 27 [2] 13 3c [2] 1c 26 [2] 02 3b [2] 00 3a [2] 1b 3c [2] 07 3b [2] 1b 14 }

  condition:
    any of them
}