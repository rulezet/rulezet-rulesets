rule TTP_XOR_MULT_DOSStub_b193 {
  strings:
    $key_b193 = { e5 fb [2] 91 e3 [2] d6 e1 [2] 91 f0 [2] df fc [2] d3 f6 [2] c4 fd [2] df b3 [2] e2 }

  condition:
    any of them
}