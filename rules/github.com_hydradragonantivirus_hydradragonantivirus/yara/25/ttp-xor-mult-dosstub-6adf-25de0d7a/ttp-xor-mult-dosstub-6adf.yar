rule TTP_XOR_MULT_DOSStub_6adf {
  strings:
    $key_6adf = { 3e b7 [2] 4a af [2] 0d ad [2] 4a bc [2] 04 b0 [2] 08 ba [2] 1f b1 [2] 04 ff [2] 39 }

  condition:
    any of them
}