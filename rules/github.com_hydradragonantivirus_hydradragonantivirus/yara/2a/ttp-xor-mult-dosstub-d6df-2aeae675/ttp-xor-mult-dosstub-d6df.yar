rule TTP_XOR_MULT_DOSStub_d6df {
  strings:
    $key_d6df = { 82 b7 [2] f6 af [2] b1 ad [2] f6 bc [2] b8 b0 [2] b4 ba [2] a3 b1 [2] b8 ff [2] 85 }

  condition:
    any of them
}