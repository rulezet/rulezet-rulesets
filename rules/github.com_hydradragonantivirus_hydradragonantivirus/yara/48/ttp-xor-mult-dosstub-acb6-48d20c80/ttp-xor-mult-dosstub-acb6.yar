rule TTP_XOR_MULT_DOSStub_acb6 {
  strings:
    $key_acb6 = { f8 de [2] 8c c6 [2] cb c4 [2] 8c d5 [2] c2 d9 [2] ce d3 [2] d9 d8 [2] c2 96 [2] ff }

  condition:
    any of them
}