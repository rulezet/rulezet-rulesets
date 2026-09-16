rule TTP_XOR_QUAD_CurrentVersionRun_62c6 {
  strings:
    $key_62c6 = { 31 a9 [2] 15 a7 [2] 3e 8b [2] 10 a9 [2] 04 b2 [2] 0b a8 [2] 15 b5 [2] 17 b4 [2] 0c b2 [2] 10 b5 [2] 0c 9a }

  condition:
    any of them
}