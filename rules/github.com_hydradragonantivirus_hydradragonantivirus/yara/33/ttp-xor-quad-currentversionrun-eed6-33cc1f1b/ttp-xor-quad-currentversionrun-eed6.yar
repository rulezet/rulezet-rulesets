rule TTP_XOR_QUAD_CurrentVersionRun_eed6 {
  strings:
    $key_eed6 = { bd b9 [2] 99 b7 [2] b2 9b [2] 9c b9 [2] 88 a2 [2] 87 b8 [2] 99 a5 [2] 9b a4 [2] 80 a2 [2] 9c a5 [2] 80 8a }

  condition:
    any of them
}