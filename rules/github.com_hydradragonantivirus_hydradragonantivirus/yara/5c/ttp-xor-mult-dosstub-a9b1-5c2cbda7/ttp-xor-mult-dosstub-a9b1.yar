rule TTP_XOR_MULT_DOSStub_a9b1 {
  strings:
    $key_a9b1 = { fd d9 [2] 89 c1 [2] ce c3 [2] 89 d2 [2] c7 de [2] cb d4 [2] dc df [2] c7 91 [2] fa }

  condition:
    any of them
}