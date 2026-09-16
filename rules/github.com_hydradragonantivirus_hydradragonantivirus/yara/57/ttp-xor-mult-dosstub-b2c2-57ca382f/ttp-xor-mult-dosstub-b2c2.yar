rule TTP_XOR_MULT_DOSStub_b2c2 {
  strings:
    $key_b2c2 = { e6 aa [2] 92 b2 [2] d5 b0 [2] 92 a1 [2] dc ad [2] d0 a7 [2] c7 ac [2] dc e2 [2] e1 }

  condition:
    any of them
}