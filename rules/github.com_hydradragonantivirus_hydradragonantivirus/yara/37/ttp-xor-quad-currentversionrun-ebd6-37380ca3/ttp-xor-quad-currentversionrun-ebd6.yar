rule TTP_XOR_QUAD_CurrentVersionRun_ebd6 {
  strings:
    $key_ebd6 = { b8 b9 [2] 9c b7 [2] b7 9b [2] 99 b9 [2] 8d a2 [2] 82 b8 [2] 9c a5 [2] 9e a4 [2] 85 a2 [2] 99 a5 [2] 85 8a }

  condition:
    any of them
}