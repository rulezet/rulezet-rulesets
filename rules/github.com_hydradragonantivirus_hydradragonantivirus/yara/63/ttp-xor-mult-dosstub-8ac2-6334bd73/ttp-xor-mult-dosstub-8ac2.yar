rule TTP_XOR_MULT_DOSStub_8ac2 {
  strings:
    $key_8ac2 = { de aa [2] aa b2 [2] ed b0 [2] aa a1 [2] e4 ad [2] e8 a7 [2] ff ac [2] e4 e2 [2] d9 }

  condition:
    any of them
}