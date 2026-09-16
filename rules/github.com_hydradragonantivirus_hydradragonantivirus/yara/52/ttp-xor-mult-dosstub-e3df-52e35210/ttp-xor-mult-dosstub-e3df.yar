rule TTP_XOR_MULT_DOSStub_e3df {
  strings:
    $key_e3df = { b7 b7 [2] c3 af [2] 84 ad [2] c3 bc [2] 8d b0 [2] 81 ba [2] 96 b1 [2] 8d ff [2] b0 }

  condition:
    any of them
}