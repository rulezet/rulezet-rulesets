rule TTP_XOR_MULT_DOSStub_a6df {
  strings:
    $key_a6df = { f2 b7 [2] 86 af [2] c1 ad [2] 86 bc [2] c8 b0 [2] c4 ba [2] d3 b1 [2] c8 ff [2] f5 }

  condition:
    any of them
}