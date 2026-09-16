rule TTP_XOR_MULT_DOSStub_e7df {
  strings:
    $key_e7df = { b3 b7 [2] c7 af [2] 80 ad [2] c7 bc [2] 89 b0 [2] 85 ba [2] 92 b1 [2] 89 ff [2] b4 }

  condition:
    any of them
}