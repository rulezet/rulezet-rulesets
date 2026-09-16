rule TTP_XOR_MULT_DOSStub_35df {
  strings:
    $key_35df = { 61 b7 [2] 15 af [2] 52 ad [2] 15 bc [2] 5b b0 [2] 57 ba [2] 40 b1 [2] 5b ff [2] 66 }

  condition:
    any of them
}