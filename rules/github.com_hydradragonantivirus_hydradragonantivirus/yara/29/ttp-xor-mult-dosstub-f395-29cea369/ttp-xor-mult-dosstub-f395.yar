rule TTP_XOR_MULT_DOSStub_f395 {
  strings:
    $key_f395 = { a7 fd [2] d3 e5 [2] 94 e7 [2] d3 f6 [2] 9d fa [2] 91 f0 [2] 86 fb [2] 9d b5 [2] a0 }

  condition:
    any of them
}