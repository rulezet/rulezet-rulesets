rule TTP_XOR_MULT_DOSStub_badf {
  strings:
    $key_badf = { ee b7 [2] 9a af [2] dd ad [2] 9a bc [2] d4 b0 [2] d8 ba [2] cf b1 [2] d4 ff [2] e9 }

  condition:
    any of them
}