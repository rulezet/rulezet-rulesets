rule TTP_XOR_MULT_DOSStub_e9a6 {
  strings:
    $key_e9a6 = { bd ce [2] c9 d6 [2] 8e d4 [2] c9 c5 [2] 87 c9 [2] 8b c3 [2] 9c c8 [2] 87 86 [2] ba }

  condition:
    any of them
}