rule TTP_XOR_QUAD_CurrentVersionRun_1f76 {
  strings:
    $key_1f76 = { 4c 19 [2] 68 17 [2] 43 3b [2] 6d 19 [2] 79 02 [2] 76 18 [2] 68 05 [2] 6a 04 [2] 71 02 [2] 6d 05 [2] 71 2a }

  condition:
    any of them
}