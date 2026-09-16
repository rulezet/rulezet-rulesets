rule TTP_XOR_MULT_DOSStub_e2c2 {
  strings:
    $key_e2c2 = { b6 aa [2] c2 b2 [2] 85 b0 [2] c2 a1 [2] 8c ad [2] 80 a7 [2] 97 ac [2] 8c e2 [2] b1 }

  condition:
    any of them
}