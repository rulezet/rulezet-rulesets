rule TTP_XOR_QUAD_CurrentVersionRun_62d6 {
  strings:
    $key_62d6 = { 31 b9 [2] 15 b7 [2] 3e 9b [2] 10 b9 [2] 04 a2 [2] 0b b8 [2] 15 a5 [2] 17 a4 [2] 0c a2 [2] 10 a5 [2] 0c 8a }

  condition:
    any of them
}