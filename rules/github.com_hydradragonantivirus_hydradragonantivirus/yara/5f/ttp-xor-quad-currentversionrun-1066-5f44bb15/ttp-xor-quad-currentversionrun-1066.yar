rule TTP_XOR_QUAD_CurrentVersionRun_1066 {
  strings:
    $key_1066 = { 43 09 [2] 67 07 [2] 4c 2b [2] 62 09 [2] 76 12 [2] 79 08 [2] 67 15 [2] 65 14 [2] 7e 12 [2] 62 15 [2] 7e 3a }

  condition:
    any of them
}