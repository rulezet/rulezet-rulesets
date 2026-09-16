rule TTP_XOR_QUAD_CurrentVersionRun_ffd6 {
  strings:
    $key_ffd6 = { ac b9 [2] 88 b7 [2] a3 9b [2] 8d b9 [2] 99 a2 [2] 96 b8 [2] 88 a5 [2] 8a a4 [2] 91 a2 [2] 8d a5 [2] 91 8a }

  condition:
    any of them
}