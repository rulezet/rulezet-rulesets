rule TTP_XOR_QUAD_CurrentVersionRun_d4aa {
  strings:
    $key_d4aa = { 87 c5 [2] a3 cb [2] 88 e7 [2] a6 c5 [2] b2 de [2] bd c4 [2] a3 d9 [2] a1 d8 [2] ba de [2] a6 d9 [2] ba f6 }

  condition:
    any of them
}