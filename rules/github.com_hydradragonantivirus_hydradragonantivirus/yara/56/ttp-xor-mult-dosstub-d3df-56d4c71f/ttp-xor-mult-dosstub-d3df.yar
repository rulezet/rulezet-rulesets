rule TTP_XOR_MULT_DOSStub_d3df {
  strings:
    $key_d3df = { 87 b7 [2] f3 af [2] b4 ad [2] f3 bc [2] bd b0 [2] b1 ba [2] a6 b1 [2] bd ff [2] 80 }

  condition:
    any of them
}