rule TTP_XOR_MULT_DOSStub_ecd7 {
  strings:
    $key_ecd7 = { b8 bf [2] cc a7 [2] 8b a5 [2] cc b4 [2] 82 b8 [2] 8e b2 [2] 99 b9 [2] 82 f7 [2] bf }

  condition:
    any of them
}