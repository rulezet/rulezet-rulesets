rule TTP_XOR_MULT_DOSStub_91df {
  strings:
    $key_91df = { c5 b7 [2] b1 af [2] f6 ad [2] b1 bc [2] ff b0 [2] f3 ba [2] e4 b1 [2] ff ff [2] c2 }

  condition:
    any of them
}