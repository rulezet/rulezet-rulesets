rule TTP_XOR_QUAD_CurrentVersionRun_14d5 {
  strings:
    $key_14d5 = { 47 ba [2] 63 b4 [2] 48 98 [2] 66 ba [2] 72 a1 [2] 7d bb [2] 63 a6 [2] 61 a7 [2] 7a a1 [2] 66 a6 [2] 7a 89 }

  condition:
    any of them
}