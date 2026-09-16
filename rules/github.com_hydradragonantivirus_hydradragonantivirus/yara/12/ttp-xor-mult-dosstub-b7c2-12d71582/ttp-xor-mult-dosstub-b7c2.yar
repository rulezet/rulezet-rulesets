rule TTP_XOR_MULT_DOSStub_b7c2 {
  strings:
    $key_b7c2 = { e3 aa [2] 97 b2 [2] d0 b0 [2] 97 a1 [2] d9 ad [2] d5 a7 [2] c2 ac [2] d9 e2 [2] e4 }

  condition:
    any of them
}