rule TTP_XOR_MULT_DOSStub_0bdf {
  strings:
    $key_0bdf = { 5f b7 [2] 2b af [2] 6c ad [2] 2b bc [2] 65 b0 [2] 69 ba [2] 7e b1 [2] 65 ff [2] 58 }

  condition:
    any of them
}