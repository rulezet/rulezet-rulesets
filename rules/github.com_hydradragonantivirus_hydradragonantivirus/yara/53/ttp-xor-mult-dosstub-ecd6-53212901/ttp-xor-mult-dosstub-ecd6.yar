rule TTP_XOR_MULT_DOSStub_ecd6 {
  strings:
    $key_ecd6 = { b8 be [2] cc a6 [2] 8b a4 [2] cc b5 [2] 82 b9 [2] 8e b3 [2] 99 b8 [2] 82 f6 [2] bf }

  condition:
    any of them
}