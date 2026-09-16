rule TTP_XOR_QUAD_CurrentVersionRun_55d6 {
  strings:
    $key_55d6 = { 06 b9 [2] 22 b7 [2] 09 9b [2] 27 b9 [2] 33 a2 [2] 3c b8 [2] 22 a5 [2] 20 a4 [2] 3b a2 [2] 27 a5 [2] 3b 8a }

  condition:
    any of them
}