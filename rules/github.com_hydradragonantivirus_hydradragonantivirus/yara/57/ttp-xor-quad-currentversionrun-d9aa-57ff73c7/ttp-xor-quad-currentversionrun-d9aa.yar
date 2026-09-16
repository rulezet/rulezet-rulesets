rule TTP_XOR_QUAD_CurrentVersionRun_d9aa {
  strings:
    $key_d9aa = { 8a c5 [2] ae cb [2] 85 e7 [2] ab c5 [2] bf de [2] b0 c4 [2] ae d9 [2] ac d8 [2] b7 de [2] ab d9 [2] b7 f6 }

  condition:
    any of them
}