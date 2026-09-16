rule TTP_XOR_MULT_DOSStub_ecc7 {
  strings:
    $key_ecc7 = { b8 af [2] cc b7 [2] 8b b5 [2] cc a4 [2] 82 a8 [2] 8e a2 [2] 99 a9 [2] 82 e7 [2] bf }

  condition:
    any of them
}