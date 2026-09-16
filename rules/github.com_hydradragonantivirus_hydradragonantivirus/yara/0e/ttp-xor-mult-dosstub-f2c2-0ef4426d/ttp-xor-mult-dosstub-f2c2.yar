rule TTP_XOR_MULT_DOSStub_f2c2 {
  strings:
    $key_f2c2 = { a6 aa [2] d2 b2 [2] 95 b0 [2] d2 a1 [2] 9c ad [2] 90 a7 [2] 87 ac [2] 9c e2 [2] a1 }

  condition:
    any of them
}