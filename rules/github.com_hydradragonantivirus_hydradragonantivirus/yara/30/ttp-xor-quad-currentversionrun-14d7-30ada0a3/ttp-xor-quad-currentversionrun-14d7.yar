rule TTP_XOR_QUAD_CurrentVersionRun_14d7 {
  strings:
    $key_14d7 = { 47 b8 [2] 63 b6 [2] 48 9a [2] 66 b8 [2] 72 a3 [2] 7d b9 [2] 63 a4 [2] 61 a5 [2] 7a a3 [2] 66 a4 [2] 7a 8b }

  condition:
    any of them
}