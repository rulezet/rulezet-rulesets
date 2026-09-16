rule TTP_XOR_MULT_DOSStub_1bdf {
  strings:
    $key_1bdf = { 4f b7 [2] 3b af [2] 7c ad [2] 3b bc [2] 75 b0 [2] 79 ba [2] 6e b1 [2] 75 ff [2] 48 }

  condition:
    any of them
}