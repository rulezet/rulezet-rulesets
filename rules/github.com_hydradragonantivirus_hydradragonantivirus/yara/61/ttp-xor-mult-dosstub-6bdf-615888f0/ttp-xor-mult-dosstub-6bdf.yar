rule TTP_XOR_MULT_DOSStub_6bdf {
  strings:
    $key_6bdf = { 3f b7 [2] 4b af [2] 0c ad [2] 4b bc [2] 05 b0 [2] 09 ba [2] 1e b1 [2] 05 ff [2] 38 }

  condition:
    any of them
}