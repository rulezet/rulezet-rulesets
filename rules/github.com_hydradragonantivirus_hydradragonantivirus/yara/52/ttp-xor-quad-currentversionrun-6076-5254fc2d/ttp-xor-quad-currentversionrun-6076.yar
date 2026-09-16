rule TTP_XOR_QUAD_CurrentVersionRun_6076 {
  strings:
    $key_6076 = { 33 19 [2] 17 17 [2] 3c 3b [2] 12 19 [2] 06 02 [2] 09 18 [2] 17 05 [2] 15 04 [2] 0e 02 [2] 12 05 [2] 0e 2a }

  condition:
    any of them
}