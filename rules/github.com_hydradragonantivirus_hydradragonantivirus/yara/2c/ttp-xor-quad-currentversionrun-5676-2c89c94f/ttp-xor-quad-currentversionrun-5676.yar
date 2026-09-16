rule TTP_XOR_QUAD_CurrentVersionRun_5676 {
  strings:
    $key_5676 = { 05 19 [2] 21 17 [2] 0a 3b [2] 24 19 [2] 30 02 [2] 3f 18 [2] 21 05 [2] 23 04 [2] 38 02 [2] 24 05 [2] 38 2a }

  condition:
    any of them
}