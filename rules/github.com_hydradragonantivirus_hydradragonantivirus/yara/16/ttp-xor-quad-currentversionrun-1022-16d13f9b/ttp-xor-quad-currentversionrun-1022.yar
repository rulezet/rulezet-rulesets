rule TTP_XOR_QUAD_CurrentVersionRun_1022 {
  strings:
    $key_1022 = { 43 4d [2] 67 43 [2] 4c 6f [2] 62 4d [2] 76 56 [2] 79 4c [2] 67 51 [2] 65 50 [2] 7e 56 [2] 62 51 [2] 7e 7e }

  condition:
    any of them
}