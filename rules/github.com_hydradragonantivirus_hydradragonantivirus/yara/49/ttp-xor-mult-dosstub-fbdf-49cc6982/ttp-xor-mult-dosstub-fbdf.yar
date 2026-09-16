rule TTP_XOR_MULT_DOSStub_fbdf {
  strings:
    $key_fbdf = { af b7 [2] db af [2] 9c ad [2] db bc [2] 95 b0 [2] 99 ba [2] 8e b1 [2] 95 ff [2] a8 }

  condition:
    any of them
}