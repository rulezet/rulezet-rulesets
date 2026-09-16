rule TTP_XOR_MULT_DOSStub_03df {
  strings:
    $key_03df = { 57 b7 [2] 23 af [2] 64 ad [2] 23 bc [2] 6d b0 [2] 61 ba [2] 76 b1 [2] 6d ff [2] 50 }

  condition:
    any of them
}