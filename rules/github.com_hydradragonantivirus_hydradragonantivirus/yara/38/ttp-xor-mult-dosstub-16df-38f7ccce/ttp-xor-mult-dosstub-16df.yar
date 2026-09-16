rule TTP_XOR_MULT_DOSStub_16df {
  strings:
    $key_16df = { 42 b7 [2] 36 af [2] 71 ad [2] 36 bc [2] 78 b0 [2] 74 ba [2] 63 b1 [2] 78 ff [2] 45 }

  condition:
    any of them
}