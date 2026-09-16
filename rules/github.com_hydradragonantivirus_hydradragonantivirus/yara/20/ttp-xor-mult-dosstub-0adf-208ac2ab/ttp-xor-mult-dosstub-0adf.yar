rule TTP_XOR_MULT_DOSStub_0adf {
  strings:
    $key_0adf = { 5e b7 [2] 2a af [2] 6d ad [2] 2a bc [2] 64 b0 [2] 68 ba [2] 7f b1 [2] 64 ff [2] 59 }

  condition:
    any of them
}