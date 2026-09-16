rule TTP_XOR_MULT_DOSStub_3adf {
  strings:
    $key_3adf = { 6e b7 [2] 1a af [2] 5d ad [2] 1a bc [2] 54 b0 [2] 58 ba [2] 4f b1 [2] 54 ff [2] 69 }

  condition:
    any of them
}