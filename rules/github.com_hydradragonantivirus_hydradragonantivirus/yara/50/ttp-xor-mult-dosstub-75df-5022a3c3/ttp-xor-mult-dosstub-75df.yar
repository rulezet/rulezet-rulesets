rule TTP_XOR_MULT_DOSStub_75df {
  strings:
    $key_75df = { 21 b7 [2] 55 af [2] 12 ad [2] 55 bc [2] 1b b0 [2] 17 ba [2] 00 b1 [2] 1b ff [2] 26 }

  condition:
    any of them
}