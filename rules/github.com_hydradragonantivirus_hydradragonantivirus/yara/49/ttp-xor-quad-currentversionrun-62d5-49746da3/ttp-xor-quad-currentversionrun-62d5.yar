rule TTP_XOR_QUAD_CurrentVersionRun_62d5 {
  strings:
    $key_62d5 = { 31 ba [2] 15 b4 [2] 3e 98 [2] 10 ba [2] 04 a1 [2] 0b bb [2] 15 a6 [2] 17 a7 [2] 0c a1 [2] 10 a6 [2] 0c 89 }

  condition:
    any of them
}