rule TTP_XOR_QUAD_CurrentVersionRun_7727 {
  strings:
    $key_7727 = { 24 48 [2] 00 46 [2] 2b 6a [2] 05 48 [2] 11 53 [2] 1e 49 [2] 00 54 [2] 02 55 [2] 19 53 [2] 05 54 [2] 19 7b }

  condition:
    any of them
}