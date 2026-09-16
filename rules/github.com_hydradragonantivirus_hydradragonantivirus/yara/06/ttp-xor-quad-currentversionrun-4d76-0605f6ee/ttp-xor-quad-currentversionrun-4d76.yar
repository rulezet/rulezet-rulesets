rule TTP_XOR_QUAD_CurrentVersionRun_4d76 {
  strings:
    $key_4d76 = { 1e 19 [2] 3a 17 [2] 11 3b [2] 3f 19 [2] 2b 02 [2] 24 18 [2] 3a 05 [2] 38 04 [2] 23 02 [2] 3f 05 [2] 23 2a }

  condition:
    any of them
}