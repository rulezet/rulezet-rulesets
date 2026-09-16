rule TTP_XOR_QUAD_CurrentVersionRun_7239 {
  strings:
    $key_7239 = { 21 56 [2] 05 58 [2] 2e 74 [2] 00 56 [2] 14 4d [2] 1b 57 [2] 05 4a [2] 07 4b [2] 1c 4d [2] 00 4a [2] 1c 65 }

  condition:
    any of them
}