rule TTP_XOR_QUAD_CurrentVersionRun_70d7 {
  strings:
    $key_70d7 = { 23 b8 [2] 07 b6 [2] 2c 9a [2] 02 b8 [2] 16 a3 [2] 19 b9 [2] 07 a4 [2] 05 a5 [2] 1e a3 [2] 02 a4 [2] 1e 8b }

  condition:
    any of them
}