rule TTP_XOR_MULT_DOSStub_31df {
  strings:
    $key_31df = { 65 b7 [2] 11 af [2] 56 ad [2] 11 bc [2] 5f b0 [2] 53 ba [2] 44 b1 [2] 5f ff [2] 62 }

  condition:
    any of them
}