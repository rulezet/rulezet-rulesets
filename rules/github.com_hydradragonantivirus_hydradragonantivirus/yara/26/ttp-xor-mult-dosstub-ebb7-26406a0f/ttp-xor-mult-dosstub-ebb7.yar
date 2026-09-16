rule TTP_XOR_MULT_DOSStub_ebb7 {
  strings:
    $key_ebb7 = { bf df [2] cb c7 [2] 8c c5 [2] cb d4 [2] 85 d8 [2] 89 d2 [2] 9e d9 [2] 85 97 [2] b8 }

  condition:
    any of them
}