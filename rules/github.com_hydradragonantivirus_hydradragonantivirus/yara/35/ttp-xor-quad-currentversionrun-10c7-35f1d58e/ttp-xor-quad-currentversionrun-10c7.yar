rule TTP_XOR_QUAD_CurrentVersionRun_10c7 {
  strings:
    $key_10c7 = { 43 a8 [2] 67 a6 [2] 4c 8a [2] 62 a8 [2] 76 b3 [2] 79 a9 [2] 67 b4 [2] 65 b5 [2] 7e b3 [2] 62 b4 [2] 7e 9b }

  condition:
    any of them
}