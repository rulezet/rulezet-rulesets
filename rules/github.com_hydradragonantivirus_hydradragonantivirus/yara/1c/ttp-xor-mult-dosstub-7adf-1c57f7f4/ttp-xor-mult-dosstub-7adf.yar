rule TTP_XOR_MULT_DOSStub_7adf {
  strings:
    $key_7adf = { 2e b7 [2] 5a af [2] 1d ad [2] 5a bc [2] 14 b0 [2] 18 ba [2] 0f b1 [2] 14 ff [2] 29 }

  condition:
    any of them
}