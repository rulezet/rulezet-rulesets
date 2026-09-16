rule TTP_XOR_MULT_DOSStub_f8df {
  strings:
    $key_f8df = { ac b7 [2] d8 af [2] 9f ad [2] d8 bc [2] 96 b0 [2] 9a ba [2] 8d b1 [2] 96 ff [2] ab }

  condition:
    any of them
}