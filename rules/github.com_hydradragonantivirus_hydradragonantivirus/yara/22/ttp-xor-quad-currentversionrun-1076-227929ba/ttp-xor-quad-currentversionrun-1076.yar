rule TTP_XOR_QUAD_CurrentVersionRun_1076 {
  strings:
    $key_1076 = { 43 19 [2] 67 17 [2] 4c 3b [2] 62 19 [2] 76 02 [2] 79 18 [2] 67 05 [2] 65 04 [2] 7e 02 [2] 62 05 [2] 7e 2a }

  condition:
    any of them
}