rule TTP_XOR_MULT_DOSStub_30df {
  strings:
    $key_30df = { 64 b7 [2] 10 af [2] 57 ad [2] 10 bc [2] 5e b0 [2] 52 ba [2] 45 b1 [2] 5e ff [2] 63 }

  condition:
    any of them
}