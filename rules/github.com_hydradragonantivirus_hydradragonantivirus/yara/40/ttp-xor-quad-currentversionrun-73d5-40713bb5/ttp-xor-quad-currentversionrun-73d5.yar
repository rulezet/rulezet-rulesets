rule TTP_XOR_QUAD_CurrentVersionRun_73d5 {
  strings:
    $key_73d5 = { 20 ba [2] 04 b4 [2] 2f 98 [2] 01 ba [2] 15 a1 [2] 1a bb [2] 04 a6 [2] 06 a7 [2] 1d a1 [2] 01 a6 [2] 1d 89 }

  condition:
    any of them
}