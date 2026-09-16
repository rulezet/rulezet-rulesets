rule TTP_XOR_QUAD_CurrentVersionRun_62d7 {
  strings:
    $key_62d7 = { 31 b8 [2] 15 b6 [2] 3e 9a [2] 10 b8 [2] 04 a3 [2] 0b b9 [2] 15 a4 [2] 17 a5 [2] 0c a3 [2] 10 a4 [2] 0c 8b }

  condition:
    any of them
}