rule TTP_XOR_MULT_DOSStub_5adf {
  strings:
    $key_5adf = { 0e b7 [2] 7a af [2] 3d ad [2] 7a bc [2] 34 b0 [2] 38 ba [2] 2f b1 [2] 34 ff [2] 09 }

  condition:
    any of them
}