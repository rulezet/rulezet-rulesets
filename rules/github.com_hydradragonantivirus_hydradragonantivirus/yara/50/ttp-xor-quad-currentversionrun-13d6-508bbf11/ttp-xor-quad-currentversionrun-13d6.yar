rule TTP_XOR_QUAD_CurrentVersionRun_13d6 {
  strings:
    $key_13d6 = { 40 b9 [2] 64 b7 [2] 4f 9b [2] 61 b9 [2] 75 a2 [2] 7a b8 [2] 64 a5 [2] 66 a4 [2] 7d a2 [2] 61 a5 [2] 7d 8a }

  condition:
    any of them
}