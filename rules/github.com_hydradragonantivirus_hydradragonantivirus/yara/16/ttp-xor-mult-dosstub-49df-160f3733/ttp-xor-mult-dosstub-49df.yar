rule TTP_XOR_MULT_DOSStub_49df {
  strings:
    $key_49df = { 1d b7 [2] 69 af [2] 2e ad [2] 69 bc [2] 27 b0 [2] 2b ba [2] 3c b1 [2] 27 ff [2] 1a }

  condition:
    any of them
}