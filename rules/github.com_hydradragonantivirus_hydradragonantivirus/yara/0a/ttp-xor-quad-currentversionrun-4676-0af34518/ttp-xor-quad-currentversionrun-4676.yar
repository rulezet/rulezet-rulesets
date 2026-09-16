rule TTP_XOR_QUAD_CurrentVersionRun_4676 {
  strings:
    $key_4676 = { 15 19 [2] 31 17 [2] 1a 3b [2] 34 19 [2] 20 02 [2] 2f 18 [2] 31 05 [2] 33 04 [2] 28 02 [2] 34 05 [2] 28 2a }

  condition:
    any of them
}