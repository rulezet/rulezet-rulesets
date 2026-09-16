rule TTP_XOR_QUAD_CurrentVersionRun_62c7 {
  strings:
    $key_62c7 = { 31 a8 [2] 15 a6 [2] 3e 8a [2] 10 a8 [2] 04 b3 [2] 0b a9 [2] 15 b4 [2] 17 b5 [2] 0c b3 [2] 10 b4 [2] 0c 9b }

  condition:
    any of them
}