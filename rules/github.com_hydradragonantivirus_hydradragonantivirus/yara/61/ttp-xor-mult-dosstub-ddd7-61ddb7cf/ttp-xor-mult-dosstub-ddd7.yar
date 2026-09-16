rule TTP_XOR_MULT_DOSStub_ddd7 {
  strings:
    $key_ddd7 = { 89 bf [2] fd a7 [2] ba a5 [2] fd b4 [2] b3 b8 [2] bf b2 [2] a8 b9 [2] b3 f7 [2] 8e }

  condition:
    any of them
}