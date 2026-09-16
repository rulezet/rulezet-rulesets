rule TTP_XOR_MULT_DOSStub_f393 {
  strings:
    $key_f393 = { a7 fb [2] d3 e3 [2] 94 e1 [2] d3 f0 [2] 9d fc [2] 91 f6 [2] 86 fd [2] 9d b3 [2] a0 }

  condition:
    any of them
}