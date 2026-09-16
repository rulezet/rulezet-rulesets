rule TTP_XOR_MULT_DOSStub_09df {
  strings:
    $key_09df = { 5d b7 [2] 29 af [2] 6e ad [2] 29 bc [2] 67 b0 [2] 6b ba [2] 7c b1 [2] 67 ff [2] 5a }

  condition:
    any of them
}