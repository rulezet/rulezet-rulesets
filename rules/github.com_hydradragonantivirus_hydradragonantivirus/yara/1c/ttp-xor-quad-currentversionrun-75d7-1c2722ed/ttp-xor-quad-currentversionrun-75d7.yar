rule TTP_XOR_QUAD_CurrentVersionRun_75d7 {
  strings:
    $key_75d7 = { 26 b8 [2] 02 b6 [2] 29 9a [2] 07 b8 [2] 13 a3 [2] 1c b9 [2] 02 a4 [2] 00 a5 [2] 1b a3 [2] 07 a4 [2] 1b 8b }

  condition:
    any of them
}