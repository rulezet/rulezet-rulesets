rule TTP_XOR_QUAD_CurrentVersionRun_6776 {
  strings:
    $key_6776 = { 34 19 [2] 10 17 [2] 3b 3b [2] 15 19 [2] 01 02 [2] 0e 18 [2] 10 05 [2] 12 04 [2] 09 02 [2] 15 05 [2] 09 2a }

  condition:
    any of them
}