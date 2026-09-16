rule TTP_XOR_QUAD_CurrentVersionRun_eed7 {
  strings:
    $key_eed7 = { bd b8 [2] 99 b6 [2] b2 9a [2] 9c b8 [2] 88 a3 [2] 87 b9 [2] 99 a4 [2] 9b a5 [2] 80 a3 [2] 9c a4 [2] 80 8b }

  condition:
    any of them
}