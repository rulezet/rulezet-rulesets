rule TTP_XOR_MULT_DOSStub_68df {
  strings:
    $key_68df = { 3c b7 [2] 48 af [2] 0f ad [2] 48 bc [2] 06 b0 [2] 0a ba [2] 1d b1 [2] 06 ff [2] 3b }

  condition:
    any of them
}