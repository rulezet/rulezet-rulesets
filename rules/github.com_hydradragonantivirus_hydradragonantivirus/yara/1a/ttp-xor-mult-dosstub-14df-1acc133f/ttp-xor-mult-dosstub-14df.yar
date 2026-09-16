rule TTP_XOR_MULT_DOSStub_14df {
  strings:
    $key_14df = { 40 b7 [2] 34 af [2] 73 ad [2] 34 bc [2] 7a b0 [2] 76 ba [2] 61 b1 [2] 7a ff [2] 47 }

  condition:
    any of them
}