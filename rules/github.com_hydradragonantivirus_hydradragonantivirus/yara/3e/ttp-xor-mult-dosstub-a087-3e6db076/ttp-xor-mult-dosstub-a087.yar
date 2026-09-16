rule TTP_XOR_MULT_DOSStub_a087 {
  strings:
    $key_a087 = { f4 ef [2] 80 f7 [2] c7 f5 [2] 80 e4 [2] ce e8 [2] c2 e2 [2] d5 e9 [2] ce a7 [2] f3 }

  condition:
    any of them
}