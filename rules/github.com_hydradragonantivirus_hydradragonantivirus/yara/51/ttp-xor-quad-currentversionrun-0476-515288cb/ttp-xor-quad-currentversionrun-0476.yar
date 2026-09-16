rule TTP_XOR_QUAD_CurrentVersionRun_0476 {
  strings:
    $key_0476 = { 57 19 [2] 73 17 [2] 58 3b [2] 76 19 [2] 62 02 [2] 6d 18 [2] 73 05 [2] 71 04 [2] 6a 02 [2] 76 05 [2] 6a 2a }

  condition:
    any of them
}