rule TTP_XOR_MULT_DOSStub_f0df {
  strings:
    $key_f0df = { a4 b7 [2] d0 af [2] 97 ad [2] d0 bc [2] 9e b0 [2] 92 ba [2] 85 b1 [2] 9e ff [2] a3 }

  condition:
    any of them
}