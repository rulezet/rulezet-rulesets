rule TTP_XOR_QUAD_CurrentVersionRun_deaa {
  strings:
    $key_deaa = { 8d c5 [2] a9 cb [2] 82 e7 [2] ac c5 [2] b8 de [2] b7 c4 [2] a9 d9 [2] ab d8 [2] b0 de [2] ac d9 [2] b0 f6 }

  condition:
    any of them
}