rule TTP_XOR_MULT_DOSStub_f2df {
  strings:
    $key_f2df = { a6 b7 [2] d2 af [2] 95 ad [2] d2 bc [2] 9c b0 [2] 90 ba [2] 87 b1 [2] 9c ff [2] a1 }

  condition:
    any of them
}