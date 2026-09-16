rule TTP_XOR_QUAD_CurrentVersionRun_7276 {
  strings:
    $key_7276 = { 21 19 [2] 05 17 [2] 2e 3b [2] 00 19 [2] 14 02 [2] 1b 18 [2] 05 05 [2] 07 04 [2] 1c 02 [2] 00 05 [2] 1c 2a }

  condition:
    any of them
}