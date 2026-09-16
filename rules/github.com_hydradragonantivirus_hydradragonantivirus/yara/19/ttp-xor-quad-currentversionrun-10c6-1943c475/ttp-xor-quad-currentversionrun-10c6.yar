rule TTP_XOR_QUAD_CurrentVersionRun_10c6 {
  strings:
    $key_10c6 = { 43 a9 [2] 67 a7 [2] 4c 8b [2] 62 a9 [2] 76 b2 [2] 79 a8 [2] 67 b5 [2] 65 b4 [2] 7e b2 [2] 62 b5 [2] 7e 9a }

  condition:
    any of them
}