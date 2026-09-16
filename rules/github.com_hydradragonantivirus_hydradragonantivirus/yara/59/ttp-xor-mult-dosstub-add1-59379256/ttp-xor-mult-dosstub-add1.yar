rule TTP_XOR_MULT_DOSStub_add1 {
  strings:
    $key_add1 = { f9 b9 [2] 8d a1 [2] ca a3 [2] 8d b2 [2] c3 be [2] cf b4 [2] d8 bf [2] c3 f1 [2] fe }

  condition:
    any of them
}