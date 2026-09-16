rule TTP_XOR_MULT_DOSStub_ebb1 {
  strings:
    $key_ebb1 = { bf d9 [2] cb c1 [2] 8c c3 [2] cb d2 [2] 85 de [2] 89 d4 [2] 9e df [2] 85 91 [2] b8 }

  condition:
    any of them
}