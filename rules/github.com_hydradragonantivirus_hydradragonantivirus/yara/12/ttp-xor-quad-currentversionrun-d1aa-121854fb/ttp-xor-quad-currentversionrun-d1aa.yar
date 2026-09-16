rule TTP_XOR_QUAD_CurrentVersionRun_d1aa {
  strings:
    $key_d1aa = { 82 c5 [2] a6 cb [2] 8d e7 [2] a3 c5 [2] b7 de [2] b8 c4 [2] a6 d9 [2] a4 d8 [2] bf de [2] a3 d9 [2] bf f6 }

  condition:
    any of them
}