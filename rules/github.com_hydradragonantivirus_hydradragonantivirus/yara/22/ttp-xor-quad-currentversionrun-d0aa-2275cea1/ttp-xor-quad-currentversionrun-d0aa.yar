rule TTP_XOR_QUAD_CurrentVersionRun_d0aa {
  strings:
    $key_d0aa = { 83 c5 [2] a7 cb [2] 8c e7 [2] a2 c5 [2] b6 de [2] b9 c4 [2] a7 d9 [2] a5 d8 [2] be de [2] a2 d9 [2] be f6 }

  condition:
    any of them
}