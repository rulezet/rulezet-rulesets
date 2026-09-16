rule TTP_XOR_QUAD_CurrentVersionRun_eec6 {
  strings:
    $key_eec6 = { bd a9 [2] 99 a7 [2] b2 8b [2] 9c a9 [2] 88 b2 [2] 87 a8 [2] 99 b5 [2] 9b b4 [2] 80 b2 [2] 9c b5 [2] 80 9a }

  condition:
    any of them
}