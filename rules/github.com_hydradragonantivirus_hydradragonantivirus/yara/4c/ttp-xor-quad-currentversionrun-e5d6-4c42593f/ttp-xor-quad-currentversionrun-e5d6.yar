rule TTP_XOR_QUAD_CurrentVersionRun_e5d6 {
  strings:
    $key_e5d6 = { b6 b9 [2] 92 b7 [2] b9 9b [2] 97 b9 [2] 83 a2 [2] 8c b8 [2] 92 a5 [2] 90 a4 [2] 8b a2 [2] 97 a5 [2] 8b 8a }

  condition:
    any of them
}