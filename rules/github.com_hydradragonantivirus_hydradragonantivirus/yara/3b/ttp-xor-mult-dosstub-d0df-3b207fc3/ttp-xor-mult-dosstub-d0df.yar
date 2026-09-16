rule TTP_XOR_MULT_DOSStub_d0df {
  strings:
    $key_d0df = { 84 b7 [2] f0 af [2] b7 ad [2] f0 bc [2] be b0 [2] b2 ba [2] a5 b1 [2] be ff [2] 83 }

  condition:
    any of them
}