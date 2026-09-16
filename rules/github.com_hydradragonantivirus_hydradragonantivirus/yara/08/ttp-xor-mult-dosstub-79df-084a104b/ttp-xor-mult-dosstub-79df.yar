rule TTP_XOR_MULT_DOSStub_79df {
  strings:
    $key_79df = { 2d b7 [2] 59 af [2] 1e ad [2] 59 bc [2] 17 b0 [2] 1b ba [2] 0c b1 [2] 17 ff [2] 2a }

  condition:
    any of them
}