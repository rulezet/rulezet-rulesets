rule TTP_XOR_QUAD_CurrentVersionRun_73d7 {
  strings:
    $key_73d7 = { 20 b8 [2] 04 b6 [2] 2f 9a [2] 01 b8 [2] 15 a3 [2] 1a b9 [2] 04 a4 [2] 06 a5 [2] 1d a3 [2] 01 a4 [2] 1d 8b }

  condition:
    any of them
}