rule TTP_XOR_QUAD_CurrentVersionRun_12d5 {
  strings:
    $key_12d5 = { 41 ba [2] 65 b4 [2] 4e 98 [2] 60 ba [2] 74 a1 [2] 7b bb [2] 65 a6 [2] 67 a7 [2] 7c a1 [2] 60 a6 [2] 7c 89 }

  condition:
    any of them
}