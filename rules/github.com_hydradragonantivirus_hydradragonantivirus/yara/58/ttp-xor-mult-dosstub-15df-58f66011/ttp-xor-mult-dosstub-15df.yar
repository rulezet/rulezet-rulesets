rule TTP_XOR_MULT_DOSStub_15df {
  strings:
    $key_15df = { 41 b7 [2] 35 af [2] 72 ad [2] 35 bc [2] 7b b0 [2] 77 ba [2] 60 b1 [2] 7b ff [2] 46 }

  condition:
    any of them
}