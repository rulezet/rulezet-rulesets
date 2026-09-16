rule TTP_XOR_QUAD_CurrentVersionRun_73d6 {
  strings:
    $key_73d6 = { 20 b9 [2] 04 b7 [2] 2f 9b [2] 01 b9 [2] 15 a2 [2] 1a b8 [2] 04 a5 [2] 06 a4 [2] 1d a2 [2] 01 a5 [2] 1d 8a }

  condition:
    any of them
}