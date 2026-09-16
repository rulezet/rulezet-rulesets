rule TTP_XOR_MULT_DOSStub_d7df {
  strings:
    $key_d7df = { 83 b7 [2] f7 af [2] b0 ad [2] f7 bc [2] b9 b0 [2] b5 ba [2] a2 b1 [2] b9 ff [2] 84 }

  condition:
    any of them
}