rule TTP_XOR_QUAD_CurrentVersionRun_40d7 {
  strings:
    $key_40d7 = { 13 b8 [2] 37 b6 [2] 1c 9a [2] 32 b8 [2] 26 a3 [2] 29 b9 [2] 37 a4 [2] 35 a5 [2] 2e a3 [2] 32 a4 [2] 2e 8b }

  condition:
    any of them
}