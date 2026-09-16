rule TTP_XOR_MULT_DOSStub_94df {
  strings:
    $key_94df = { c0 b7 [2] b4 af [2] f3 ad [2] b4 bc [2] fa b0 [2] f6 ba [2] e1 b1 [2] fa ff [2] c7 }

  condition:
    any of them
}