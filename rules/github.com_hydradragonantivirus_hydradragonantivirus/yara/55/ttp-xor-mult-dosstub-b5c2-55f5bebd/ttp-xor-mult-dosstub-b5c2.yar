rule TTP_XOR_MULT_DOSStub_b5c2 {
  strings:
    $key_b5c2 = { e1 aa [2] 95 b2 [2] d2 b0 [2] 95 a1 [2] db ad [2] d7 a7 [2] c0 ac [2] db e2 [2] e6 }

  condition:
    any of them
}