rule TTP_XOR_QUAD_CurrentVersionRun_22d5 {
  strings:
    $key_22d5 = { 71 ba [2] 55 b4 [2] 7e 98 [2] 50 ba [2] 44 a1 [2] 4b bb [2] 55 a6 [2] 57 a7 [2] 4c a1 [2] 50 a6 [2] 4c 89 }

  condition:
    any of them
}