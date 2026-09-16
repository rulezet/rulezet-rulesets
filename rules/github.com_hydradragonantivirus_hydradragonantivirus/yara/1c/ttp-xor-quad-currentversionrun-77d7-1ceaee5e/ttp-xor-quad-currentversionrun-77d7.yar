rule TTP_XOR_QUAD_CurrentVersionRun_77d7 {
  strings:
    $key_77d7 = { 24 b8 [2] 00 b6 [2] 2b 9a [2] 05 b8 [2] 11 a3 [2] 1e b9 [2] 00 a4 [2] 02 a5 [2] 19 a3 [2] 05 a4 [2] 19 8b }

  condition:
    any of them
}