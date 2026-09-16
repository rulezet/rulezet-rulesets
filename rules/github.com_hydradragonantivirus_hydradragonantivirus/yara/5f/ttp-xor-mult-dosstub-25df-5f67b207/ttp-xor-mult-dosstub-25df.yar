rule TTP_XOR_MULT_DOSStub_25df {
  strings:
    $key_25df = { 71 b7 [2] 05 af [2] 42 ad [2] 05 bc [2] 4b b0 [2] 47 ba [2] 50 b1 [2] 4b ff [2] 76 }

  condition:
    any of them
}