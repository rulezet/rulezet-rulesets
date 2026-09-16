rule TTP_XOR_QUAD_CurrentVersionRun_34d5 {
  strings:
    $key_34d5 = { 67 ba [2] 43 b4 [2] 68 98 [2] 46 ba [2] 52 a1 [2] 5d bb [2] 43 a6 [2] 41 a7 [2] 5a a1 [2] 46 a6 [2] 5a 89 }

  condition:
    any of them
}