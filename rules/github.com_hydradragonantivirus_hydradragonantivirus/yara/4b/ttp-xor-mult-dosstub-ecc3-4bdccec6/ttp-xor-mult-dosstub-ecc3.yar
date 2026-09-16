rule TTP_XOR_MULT_DOSStub_ecc3 {
  strings:
    $key_ecc3 = { b8 ab [2] cc b3 [2] 8b b1 [2] cc a0 [2] 82 ac [2] 8e a6 [2] 99 ad [2] 82 e3 [2] bf }

  condition:
    any of them
}