rule TTP_XOR_MULT_DOSStub_a9b6 {
  strings:
    $key_a9b6 = { fd de [2] 89 c6 [2] ce c4 [2] 89 d5 [2] c7 d9 [2] cb d3 [2] dc d8 [2] c7 96 [2] fa }

  condition:
    any of them
}