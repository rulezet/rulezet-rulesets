rule TTP_XOR_MULT_DOSStub_ac87 {
  strings:
    $key_ac87 = { f8 ef [2] 8c f7 [2] cb f5 [2] 8c e4 [2] c2 e8 [2] ce e2 [2] d9 e9 [2] c2 a7 [2] ff }

  condition:
    any of them
}