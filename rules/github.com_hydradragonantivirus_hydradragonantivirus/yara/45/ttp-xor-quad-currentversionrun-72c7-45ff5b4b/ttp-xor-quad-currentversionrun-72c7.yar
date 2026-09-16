rule TTP_XOR_QUAD_CurrentVersionRun_72c7 {
  strings:
    $key_72c7 = { 21 a8 [2] 05 a6 [2] 2e 8a [2] 00 a8 [2] 14 b3 [2] 1b a9 [2] 05 b4 [2] 07 b5 [2] 1c b3 [2] 00 b4 [2] 1c 9b }

  condition:
    any of them
}