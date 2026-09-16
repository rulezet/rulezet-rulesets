rule TTP_XOR_MULT_DOSStub_a0df {
  strings:
    $key_a0df = { f4 b7 [2] 80 af [2] c7 ad [2] 80 bc [2] ce b0 [2] c2 ba [2] d5 b1 [2] ce ff [2] f3 }

  condition:
    any of them
}