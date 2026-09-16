rule TTP_XOR_QUAD_CurrentVersionRun_1037 {
  strings:
    $key_1037 = { 43 58 [2] 67 56 [2] 4c 7a [2] 62 58 [2] 76 43 [2] 79 59 [2] 67 44 [2] 65 45 [2] 7e 43 [2] 62 44 [2] 7e 6b }

  condition:
    any of them
}