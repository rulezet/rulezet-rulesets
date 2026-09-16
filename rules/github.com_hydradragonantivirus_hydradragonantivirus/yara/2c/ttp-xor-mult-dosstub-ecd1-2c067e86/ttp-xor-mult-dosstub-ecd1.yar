rule TTP_XOR_MULT_DOSStub_ecd1 {
  strings:
    $key_ecd1 = { b8 b9 [2] cc a1 [2] 8b a3 [2] cc b2 [2] 82 be [2] 8e b4 [2] 99 bf [2] 82 f1 [2] bf }

  condition:
    any of them
}