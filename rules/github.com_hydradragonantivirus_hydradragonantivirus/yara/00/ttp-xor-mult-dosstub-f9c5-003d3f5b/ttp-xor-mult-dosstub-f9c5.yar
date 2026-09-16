rule TTP_XOR_MULT_DOSStub_f9c5 {
  strings:
    $key_f9c5 = { ad ad [2] d9 b5 [2] 9e b7 [2] d9 a6 [2] 97 aa [2] 9b a0 [2] 8c ab [2] 97 e5 [2] aa }

  condition:
    any of them
}