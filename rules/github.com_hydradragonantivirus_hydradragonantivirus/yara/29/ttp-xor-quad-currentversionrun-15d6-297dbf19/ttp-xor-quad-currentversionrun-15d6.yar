rule TTP_XOR_QUAD_CurrentVersionRun_15d6 {
  strings:
    $key_15d6 = { 46 b9 [2] 62 b7 [2] 49 9b [2] 67 b9 [2] 73 a2 [2] 7c b8 [2] 62 a5 [2] 60 a4 [2] 7b a2 [2] 67 a5 [2] 7b 8a }

  condition:
    any of them
}