rule TTP_XOR_QUAD_CurrentVersionRun_7776 {
  strings:
    $key_7776 = { 24 19 [2] 00 17 [2] 2b 3b [2] 05 19 [2] 11 02 [2] 1e 18 [2] 00 05 [2] 02 04 [2] 19 02 [2] 05 05 [2] 19 2a }

  condition:
    any of them
}