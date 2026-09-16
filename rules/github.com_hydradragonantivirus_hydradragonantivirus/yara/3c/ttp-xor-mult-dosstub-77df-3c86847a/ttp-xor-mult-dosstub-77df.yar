rule TTP_XOR_MULT_DOSStub_77df {
  strings:
    $key_77df = { 23 b7 [2] 57 af [2] 10 ad [2] 57 bc [2] 19 b0 [2] 15 ba [2] 02 b1 [2] 19 ff [2] 24 }

  condition:
    any of them
}