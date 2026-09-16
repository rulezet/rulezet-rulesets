rule TTP_XOR_QUAD_CurrentVersionRun_d146 {
  strings:
    $key_d146 = { 82 29 [2] a6 27 [2] 8d 0b [2] a3 29 [2] b7 32 [2] b8 28 [2] a6 35 [2] a4 34 [2] bf 32 [2] a3 35 [2] bf 1a }

  condition:
    any of them
}