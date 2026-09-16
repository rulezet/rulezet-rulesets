rule TTP_XOR_MULT_DOSStub_ac81 {
  strings:
    $key_ac81 = { f8 e9 [2] 8c f1 [2] cb f3 [2] 8c e2 [2] c2 ee [2] ce e4 [2] d9 ef [2] c2 a1 [2] ff }

  condition:
    any of them
}