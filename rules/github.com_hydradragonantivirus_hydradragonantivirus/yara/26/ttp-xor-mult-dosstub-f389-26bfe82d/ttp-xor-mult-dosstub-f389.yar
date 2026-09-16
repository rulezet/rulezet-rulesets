rule TTP_XOR_MULT_DOSStub_f389 {
  strings:
    $key_f389 = { a7 e1 [2] d3 f9 [2] 94 fb [2] d3 ea [2] 9d e6 [2] 91 ec [2] 86 e7 [2] 9d a9 [2] a0 }

  condition:
    any of them
}