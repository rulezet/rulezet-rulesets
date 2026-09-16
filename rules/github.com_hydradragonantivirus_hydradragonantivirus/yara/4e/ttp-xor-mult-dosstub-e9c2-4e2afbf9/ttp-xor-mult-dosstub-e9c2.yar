rule TTP_XOR_MULT_DOSStub_e9c2 {
  strings:
    $key_e9c2 = { bd aa [2] c9 b2 [2] 8e b0 [2] c9 a1 [2] 87 ad [2] 8b a7 [2] 9c ac [2] 87 e2 [2] ba }

  condition:
    any of them
}