rule TTP_XOR_MULT_DOSStub_85df {
  strings:
    $key_85df = { d1 b7 [2] a5 af [2] e2 ad [2] a5 bc [2] eb b0 [2] e7 ba [2] f0 b1 [2] eb ff [2] d6 }

  condition:
    any of them
}