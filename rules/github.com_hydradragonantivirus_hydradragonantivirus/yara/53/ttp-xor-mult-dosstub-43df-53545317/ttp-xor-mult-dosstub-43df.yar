rule TTP_XOR_MULT_DOSStub_43df {
  strings:
    $key_43df = { 17 b7 [2] 63 af [2] 24 ad [2] 63 bc [2] 2d b0 [2] 21 ba [2] 36 b1 [2] 2d ff [2] 10 }

  condition:
    any of them
}