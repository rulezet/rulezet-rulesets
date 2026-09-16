rule TTP_XOR_MULT_DOSStub_e0df {
  strings:
    $key_e0df = { b4 b7 [2] c0 af [2] 87 ad [2] c0 bc [2] 8e b0 [2] 82 ba [2] 95 b1 [2] 8e ff [2] b3 }

  condition:
    any of them
}