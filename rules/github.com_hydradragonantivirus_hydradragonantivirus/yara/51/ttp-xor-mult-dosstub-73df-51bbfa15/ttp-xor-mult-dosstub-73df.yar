rule TTP_XOR_MULT_DOSStub_73df {
  strings:
    $key_73df = { 27 b7 [2] 53 af [2] 14 ad [2] 53 bc [2] 1d b0 [2] 11 ba [2] 06 b1 [2] 1d ff [2] 20 }

  condition:
    any of them
}