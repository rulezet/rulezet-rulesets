rule TTP_XOR_QUAD_CurrentVersionRun_2776 {
  strings:
    $key_2776 = { 74 19 [2] 50 17 [2] 7b 3b [2] 55 19 [2] 41 02 [2] 4e 18 [2] 50 05 [2] 52 04 [2] 49 02 [2] 55 05 [2] 49 2a }

  condition:
    any of them
}