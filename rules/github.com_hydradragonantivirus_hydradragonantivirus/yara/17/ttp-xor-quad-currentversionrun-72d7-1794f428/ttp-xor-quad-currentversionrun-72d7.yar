rule TTP_XOR_QUAD_CurrentVersionRun_72d7 {
  strings:
    $key_72d7 = { 21 b8 [2] 05 b6 [2] 2e 9a [2] 00 b8 [2] 14 a3 [2] 1b b9 [2] 05 a4 [2] 07 a5 [2] 1c a3 [2] 00 a4 [2] 1c 8b }

  condition:
    any of them
}