rule TTP_XOR_MULT_DOSStub_ecc9 {
  strings:
    $key_ecc9 = { b8 a1 [2] cc b9 [2] 8b bb [2] cc aa [2] 82 a6 [2] 8e ac [2] 99 a7 [2] 82 e9 [2] bf }

  condition:
    any of them
}