rule TTP_XOR_MULT_DOSStub_e2df {
  strings:
    $key_e2df = { b6 b7 [2] c2 af [2] 85 ad [2] c2 bc [2] 8c b0 [2] 80 ba [2] 97 b1 [2] 8c ff [2] b1 }

  condition:
    any of them
}