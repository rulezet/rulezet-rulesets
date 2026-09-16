rule TTP_XOR_QUAD_CurrentVersionRun_7775 {
  strings:
    $key_7775 = { 24 1a [2] 00 14 [2] 2b 38 [2] 05 1a [2] 11 01 [2] 1e 1b [2] 00 06 [2] 02 07 [2] 19 01 [2] 05 06 [2] 19 29 }

  condition:
    any of them
}