rule TTP_XOR_MULT_DOSStub_56df {
  strings:
    $key_56df = { 02 b7 [2] 76 af [2] 31 ad [2] 76 bc [2] 38 b0 [2] 34 ba [2] 23 b1 [2] 38 ff [2] 05 }

  condition:
    any of them
}