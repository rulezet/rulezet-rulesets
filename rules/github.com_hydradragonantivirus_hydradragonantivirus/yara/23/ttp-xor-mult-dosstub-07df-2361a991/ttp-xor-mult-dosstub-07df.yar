rule TTP_XOR_MULT_DOSStub_07df {
  strings:
    $key_07df = { 53 b7 [2] 27 af [2] 60 ad [2] 27 bc [2] 69 b0 [2] 65 ba [2] 72 b1 [2] 69 ff [2] 54 }

  condition:
    any of them
}