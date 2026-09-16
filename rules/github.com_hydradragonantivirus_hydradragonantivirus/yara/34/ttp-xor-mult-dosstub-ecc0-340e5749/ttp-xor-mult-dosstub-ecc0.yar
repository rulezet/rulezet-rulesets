rule TTP_XOR_MULT_DOSStub_ecc0 {
  strings:
    $key_ecc0 = { b8 a8 [2] cc b0 [2] 8b b2 [2] cc a3 [2] 82 af [2] 8e a5 [2] 99 ae [2] 82 e0 [2] bf }

  condition:
    any of them
}