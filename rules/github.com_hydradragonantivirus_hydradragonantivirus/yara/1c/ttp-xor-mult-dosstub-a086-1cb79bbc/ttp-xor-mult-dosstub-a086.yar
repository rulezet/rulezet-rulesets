rule TTP_XOR_MULT_DOSStub_a086 {
  strings:
    $key_a086 = { f4 ee [2] 80 f6 [2] c7 f4 [2] 80 e5 [2] ce e9 [2] c2 e3 [2] d5 e8 [2] ce a6 [2] f3 }

  condition:
    any of them
}