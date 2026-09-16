rule TTP_XOR_MULT_DOSStub_92df {
  strings:
    $key_92df = { c6 b7 [2] b2 af [2] f5 ad [2] b2 bc [2] fc b0 [2] f0 ba [2] e7 b1 [2] fc ff [2] c1 }

  condition:
    any of them
}