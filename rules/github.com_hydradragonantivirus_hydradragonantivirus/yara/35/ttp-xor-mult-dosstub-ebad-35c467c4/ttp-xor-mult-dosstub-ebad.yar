rule TTP_XOR_MULT_DOSStub_ebad {
  strings:
    $key_ebad = { bf c5 [2] cb dd [2] 8c df [2] cb ce [2] 85 c2 [2] 89 c8 [2] 9e c3 [2] 85 8d [2] b8 }

  condition:
    any of them
}