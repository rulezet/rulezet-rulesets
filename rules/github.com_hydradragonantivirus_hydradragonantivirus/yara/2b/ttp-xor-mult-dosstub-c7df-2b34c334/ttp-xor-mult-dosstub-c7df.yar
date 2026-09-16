rule TTP_XOR_MULT_DOSStub_c7df {
  strings:
    $key_c7df = { 93 b7 [2] e7 af [2] a0 ad [2] e7 bc [2] a9 b0 [2] a5 ba [2] b2 b1 [2] a9 ff [2] 94 }

  condition:
    any of them
}