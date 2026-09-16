rule TTP_XOR_MULT_DOSStub_d4df {
  strings:
    $key_d4df = { 80 b7 [2] f4 af [2] b3 ad [2] f4 bc [2] ba b0 [2] b6 ba [2] a1 b1 [2] ba ff [2] 87 }

  condition:
    any of them
}