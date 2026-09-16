rule TTP_XOR_MULT_DOSStub_4bdf {
  strings:
    $key_4bdf = { 1f b7 [2] 6b af [2] 2c ad [2] 6b bc [2] 25 b0 [2] 29 ba [2] 3e b1 [2] 25 ff [2] 18 }

  condition:
    any of them
}