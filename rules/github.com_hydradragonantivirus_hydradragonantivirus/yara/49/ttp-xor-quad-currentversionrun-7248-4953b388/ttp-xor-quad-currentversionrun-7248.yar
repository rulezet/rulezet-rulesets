rule TTP_XOR_QUAD_CurrentVersionRun_7248 {
  strings:
    $key_7248 = { 21 27 [2] 05 29 [2] 2e 05 [2] 00 27 [2] 14 3c [2] 1b 26 [2] 05 3b [2] 07 3a [2] 1c 3c [2] 00 3b [2] 1c 14 }

  condition:
    any of them
}