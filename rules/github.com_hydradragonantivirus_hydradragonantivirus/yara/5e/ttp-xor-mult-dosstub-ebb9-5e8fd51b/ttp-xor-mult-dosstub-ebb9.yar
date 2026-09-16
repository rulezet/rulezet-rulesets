rule TTP_XOR_MULT_DOSStub_ebb9 {
  strings:
    $key_ebb9 = { bf d1 [2] cb c9 [2] 8c cb [2] cb da [2] 85 d6 [2] 89 dc [2] 9e d7 [2] 85 99 [2] b8 }

  condition:
    any of them
}