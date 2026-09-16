rule TTP_XOR_MULT_DOSStub_ddd0 {
  strings:
    $key_ddd0 = { 89 b8 [2] fd a0 [2] ba a2 [2] fd b3 [2] b3 bf [2] bf b5 [2] a8 be [2] b3 f0 [2] 8e }

  condition:
    any of them
}