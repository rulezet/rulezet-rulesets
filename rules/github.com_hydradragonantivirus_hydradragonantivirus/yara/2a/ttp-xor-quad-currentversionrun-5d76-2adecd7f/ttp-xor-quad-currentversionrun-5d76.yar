rule TTP_XOR_QUAD_CurrentVersionRun_5d76 {
  strings:
    $key_5d76 = { 0e 19 [2] 2a 17 [2] 01 3b [2] 2f 19 [2] 3b 02 [2] 34 18 [2] 2a 05 [2] 28 04 [2] 33 02 [2] 2f 05 [2] 33 2a }

  condition:
    any of them
}