rule TTP_XOR_MULT_DOSStub_ecda {
  strings:
    $key_ecda = { b8 b2 [2] cc aa [2] 8b a8 [2] cc b9 [2] 82 b5 [2] 8e bf [2] 99 b4 [2] 82 fa [2] bf }

  condition:
    any of them
}