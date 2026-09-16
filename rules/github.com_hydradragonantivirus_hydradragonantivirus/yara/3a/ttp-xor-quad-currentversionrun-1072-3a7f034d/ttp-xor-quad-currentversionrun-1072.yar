rule TTP_XOR_QUAD_CurrentVersionRun_1072 {
  strings:
    $key_1072 = { 43 1d [2] 67 13 [2] 4c 3f [2] 62 1d [2] 76 06 [2] 79 1c [2] 67 01 [2] 65 00 [2] 7e 06 [2] 62 01 [2] 7e 2e }

  condition:
    any of them
}