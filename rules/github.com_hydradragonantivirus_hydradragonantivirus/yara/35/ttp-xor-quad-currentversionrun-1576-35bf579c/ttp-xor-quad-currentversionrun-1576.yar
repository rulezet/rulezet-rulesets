rule TTP_XOR_QUAD_CurrentVersionRun_1576 {
  strings:
    $key_1576 = { 46 19 [2] 62 17 [2] 49 3b [2] 67 19 [2] 73 02 [2] 7c 18 [2] 62 05 [2] 60 04 [2] 7b 02 [2] 67 05 [2] 7b 2a }

  condition:
    any of them
}